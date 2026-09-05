"""
Entropy and byte-distribution analysis.

This module provides reusable byte-level statistical features for the
pharos-cdr extraction pipeline.

The primary purpose is to identify unusual regions of a file that may
correspond to:

- compressed data
- encrypted data
- packed payloads
- encoded blobs
- embedded objects
- obfuscated scripts
- high-entropy malicious payloads

Important:
    High entropy is NOT synonymous with malware.

Legitimate formats such as images, compressed archives, encrypted documents,
and compressed embedded resources can naturally have high entropy. Entropy
features should therefore be combined with structural, semantic, and
behavioral features elsewhere in the extraction pipeline.

The module intentionally has no dependency on Office/VBA/script parsers.
"""

from __future__ import annotations

import math
import os
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from statistics import mean, pstdev
from typing import Any, Iterable, Sequence

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_BYTE_VALUE = 255
BYTE_ALPHABET_SIZE = 256
MAX_SHANNON_ENTROPY = 8.0

DEFAULT_CHUNK_SIZE = 4096
DEFAULT_WINDOW_SIZE = 4096
DEFAULT_WINDOW_STEP = 2048
DEFAULT_MAX_SAMPLE_SIZE = 4 * 1024 * 1024

# These are heuristic thresholds, not malware thresholds.
#
# > 7.0:
#     strongly uniform byte distribution; commonly seen in compressed or
#     encrypted material.
#
# < 2.0:
#     very repetitive / structured data.
HIGH_ENTROPY_THRESHOLD = 7.0
VERY_HIGH_ENTROPY_THRESHOLD = 7.5
LOW_ENTROPY_THRESHOLD = 2.0

# A chunk is considered a "significant" entropy jump if adjacent chunks differ
# by at least this amount.
ENTROPY_TRANSITION_THRESHOLD = 1.5


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EntropyStats:
    """Summary statistics for a sequence of entropy measurements."""

    count: int
    minimum: float
    maximum: float
    mean: float
    standard_deviation: float
    median: float
    high_entropy_count: int
    very_high_entropy_count: int
    low_entropy_count: int
    high_entropy_ratio: float
    very_high_entropy_ratio: float
    low_entropy_ratio: float
    transition_count: int
    maximum_transition: float

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "count": self.count,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "mean": self.mean,
            "standard_deviation": self.standard_deviation,
            "median": self.median,
            "high_entropy_count": self.high_entropy_count,
            "very_high_entropy_count": self.very_high_entropy_count,
            "low_entropy_count": self.low_entropy_count,
            "high_entropy_ratio": self.high_entropy_ratio,
            "very_high_entropy_ratio": self.very_high_entropy_ratio,
            "low_entropy_ratio": self.low_entropy_ratio,
            "transition_count": self.transition_count,
            "maximum_transition": self.maximum_transition,
        }


# ---------------------------------------------------------------------------
# Basic entropy functions
# ---------------------------------------------------------------------------


def shannon_entropy(data: bytes | bytearray | memoryview) -> float:
    """
    Calculate Shannon entropy in bits per byte.

    The theoretical range is:

        0.0 <= entropy <= 8.0

    Examples:

        b"AAAAAA" -> approximately 0
        uniform 256-byte distribution -> 8

    Empty input returns 0.0.
    """
    if not data:
        return 0.0

    if isinstance(data, memoryview):
        data = data.tobytes()

    counts = Counter(data)
    length = len(data)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def normalized_entropy(data: bytes | bytearray | memoryview) -> float:
    """
    Calculate Shannon entropy normalized to [0, 1].

    This is useful when feature schemas prefer comparable normalized values.

    0.0:
        Completely repetitive data.

    1.0:
        Maximum possible byte-level entropy.
    """
    return shannon_entropy(data) / MAX_SHANNON_ENTROPY


def entropy_loss(
    data: bytes | bytearray | memoryview,
) -> float:
    """
    Calculate the amount of entropy remaining below the theoretical maximum.

    Returns:

        8.0 - Shannon entropy

    Lower values indicate a distribution closer to uniformly distributed
    bytes.
    """
    return MAX_SHANNON_ENTROPY - shannon_entropy(data)


# ---------------------------------------------------------------------------
# Distribution features
# ---------------------------------------------------------------------------


def byte_frequency_distribution(
    data: bytes | bytearray | memoryview,
) -> list[float]:
    """
    Return the normalized frequency of all 256 possible byte values.

    The resulting list always has exactly 256 entries.

    Index:
        0   -> frequency of 0x00
        1   -> frequency of 0x01
        ...
        255 -> frequency of 0xFF
    """
    if not data:
        return [0.0] * BYTE_ALPHABET_SIZE

    counts = [0] * BYTE_ALPHABET_SIZE

    for value in data:
        counts[value] += 1

    length = len(data)

    return [count / length for count in counts]


def unique_byte_count(
    data: bytes | bytearray | memoryview,
) -> int:
    """Return the number of distinct byte values observed."""
    if not data:
        return 0

    return len(set(data))


def byte_diversity(
    data: bytes | bytearray | memoryview,
) -> float:
    """
    Return the fraction of the 256-byte alphabet observed.

    Range:
        0.0 -> no data
        1.0 -> all possible byte values occur
    """
    return unique_byte_count(data) / BYTE_ALPHABET_SIZE


def most_common_byte_ratio(
    data: bytes | bytearray | memoryview,
) -> float:
    """
    Return the frequency of the most common byte.

    Highly repetitive content will have a high value.

    Example:
        b"AAAAAAAA" -> 1.0
    """
    if not data:
        return 0.0

    counts = Counter(data)
    return max(counts.values()) / len(data)


def byte_distribution_uniformity(
    data: bytes | bytearray | memoryview,
) -> float:
    """
    Measure how close the observed byte distribution is to uniform.

    This is derived from the L1 distance between the observed distribution
    and a perfectly uniform 256-value distribution.

    Range:
        0.0 -> maximally non-uniform
        1.0 -> perfectly uniform

    Unlike Shannon entropy, this metric is based directly on distribution
    distance.
    """
    if not data:
        return 0.0

    distribution = byte_frequency_distribution(data)
    expected = 1.0 / BYTE_ALPHABET_SIZE

    l1_distance = sum(abs(value - expected) for value in distribution)

    # Maximum L1 distance between a probability distribution and uniform
    # distribution is approximately 2 * (1 - 1/N).
    maximum_distance = 2.0 * (1.0 - expected)

    if maximum_distance == 0.0:
        return 1.0

    return max(
        0.0,
        min(
            1.0,
            1.0 - (l1_distance / maximum_distance),
        ),
    )


# ---------------------------------------------------------------------------
# Character / byte-class statistics
# ---------------------------------------------------------------------------


def printable_ratio(
    data: bytes | bytearray | memoryview,
) -> float:
    """
    Return the ratio of bytes that are ASCII printable or common whitespace.

    Included whitespace:

        TAB     0x09
        LF      0x0A
        CR      0x0D

    ASCII printable range:

        0x20 - 0x7E
    """
    if not data:
        return 0.0

    printable = sum(1 for value in data if value in (9, 10, 13) or 32 <= value <= 126)

    return printable / len(data)


def ascii_ratio(
    data: bytes | bytearray | memoryview,
) -> float:
    """Return the proportion of bytes below 0x80."""
    if not data:
        return 0.0

    return sum(value < 128 for value in data) / len(data)


def high_byte_ratio(
    data: bytes | bytearray | memoryview,
) -> float:
    """Return the proportion of bytes >= 0x80."""
    if not data:
        return 0.0

    return sum(value >= 128 for value in data) / len(data)


def null_byte_ratio(
    data: bytes | bytearray | memoryview,
) -> float:
    """Return the proportion of NULL bytes."""
    if not data:
        return 0.0

    return data.count(0) / len(data)


def control_byte_ratio(
    data: bytes | bytearray | memoryview,
) -> float:
    """
    Return the proportion of ASCII control bytes.

    This includes 0x00 through 0x1F and 0x7F.
    """
    if not data:
        return 0.0

    control = sum(1 for value in data if value <= 0x1F or value == 0x7F)

    return control / len(data)


# ---------------------------------------------------------------------------
# Chunk-level entropy
# ---------------------------------------------------------------------------


def chunk_entropy(
    data: bytes | bytearray | memoryview,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    include_partial: bool = True,
) -> list[float]:
    """
    Calculate entropy for consecutive fixed-size chunks.

    Parameters
    ----------
    data:
        Input bytes.

    chunk_size:
        Number of bytes in each chunk.

    include_partial:
        Whether to calculate entropy for a final incomplete chunk.

    Returns
    -------
    list[float]
        One entropy value per chunk.

    Notes
    -----
    Chunk entropy is particularly useful for identifying files where only
    localized regions are high entropy.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    if not data:
        return []

    if isinstance(data, memoryview):
        data = data.tobytes()

    result: list[float] = []

    for offset in range(0, len(data), chunk_size):
        chunk = data[offset : offset + chunk_size]

        if len(chunk) < chunk_size and not include_partial:
            break

        result.append(shannon_entropy(chunk))

    return result


def sliding_window_entropy(
    data: bytes | bytearray | memoryview,
    *,
    window_size: int = DEFAULT_WINDOW_SIZE,
    step: int = DEFAULT_WINDOW_STEP,
) -> list[float]:
    """
    Calculate entropy using overlapping sliding windows.

    Parameters
    ----------
    window_size:
        Size of each window.

    step:
        Distance between successive windows.

    Returns
    -------
    list[float]
        Entropy measurements for each complete window.

    A partial final window is intentionally excluded because entropy estimates
    become less comparable as window sizes vary.
    """
    if window_size <= 0:
        raise ValueError("window_size must be greater than zero")

    if step <= 0:
        raise ValueError("step must be greater than zero")

    if not data or len(data) < window_size:
        return []

    if isinstance(data, memoryview):
        data = data.tobytes()

    result: list[float] = []

    for offset in range(0, len(data) - window_size + 1, step):
        window = data[offset : offset + window_size]
        result.append(shannon_entropy(window))

    return result


# ---------------------------------------------------------------------------
# Entropy statistics
# ---------------------------------------------------------------------------


def _median(values: Sequence[float]) -> float:
    """Calculate median without introducing a dependency on NumPy."""
    if not values:
        return 0.0

    ordered = sorted(values)
    middle = len(ordered) // 2

    if len(ordered) % 2:
        return ordered[middle]

    return (ordered[middle - 1] + ordered[middle]) / 2.0


def entropy_statistics(
    values: Sequence[float],
    *,
    high_threshold: float = HIGH_ENTROPY_THRESHOLD,
    very_high_threshold: float = VERY_HIGH_ENTROPY_THRESHOLD,
    low_threshold: float = LOW_ENTROPY_THRESHOLD,
    transition_threshold: float = ENTROPY_TRANSITION_THRESHOLD,
) -> EntropyStats:
    """
    Calculate summary statistics over entropy measurements.

    The input is normally the result of `chunk_entropy()` or
    `sliding_window_entropy()`.
    """
    if high_threshold > MAX_SHANNON_ENTROPY:
        raise ValueError("high_threshold cannot exceed 8.0")

    if very_high_threshold > MAX_SHANNON_ENTROPY:
        raise ValueError("very_high_threshold cannot exceed 8.0")

    if low_threshold < 0.0:
        raise ValueError("low_threshold cannot be negative")

    if very_high_threshold < high_threshold:
        raise ValueError("very_high_threshold must be >= high_threshold")

    if transition_threshold < 0.0:
        raise ValueError("transition_threshold cannot be negative")

    if not values:
        return EntropyStats(
            count=0,
            minimum=0.0,
            maximum=0.0,
            mean=0.0,
            standard_deviation=0.0,
            median=0.0,
            high_entropy_count=0,
            very_high_entropy_count=0,
            low_entropy_count=0,
            high_entropy_ratio=0.0,
            very_high_entropy_ratio=0.0,
            low_entropy_ratio=0.0,
            transition_count=0,
            maximum_transition=0.0,
        )

    normalized = [max(0.0, min(MAX_SHANNON_ENTROPY, float(value))) for value in values]

    count = len(normalized)

    high_count = sum(value >= high_threshold for value in normalized)

    very_high_count = sum(value >= very_high_threshold for value in normalized)

    low_count = sum(value <= low_threshold for value in normalized)

    transitions = [
        abs(current - previous)
        for previous, current in zip(
            normalized,
            normalized[1:],
        )
    ]

    significant_transitions = sum(
        transition >= transition_threshold for transition in transitions
    )

    maximum_transition = max(transitions, default=0.0)

    return EntropyStats(
        count=count,
        minimum=min(normalized),
        maximum=max(normalized),
        mean=mean(normalized),
        standard_deviation=pstdev(normalized) if count > 1 else 0.0,
        median=_median(normalized),
        high_entropy_count=high_count,
        very_high_entropy_count=very_high_count,
        low_entropy_count=low_count,
        high_entropy_ratio=high_count / count,
        very_high_entropy_ratio=very_high_count / count,
        low_entropy_ratio=low_count / count,
        transition_count=significant_transitions,
        maximum_transition=maximum_transition,
    )


# ---------------------------------------------------------------------------
# Region detection
# ---------------------------------------------------------------------------


def high_entropy_regions(
    data: bytes | bytearray | memoryview,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    threshold: float = HIGH_ENTROPY_THRESHOLD,
    minimum_consecutive_chunks: int = 1,
) -> list[dict[str, Any]]:
    """
    Identify contiguous high-entropy regions.

    A region is formed when consecutive chunks have entropy >= `threshold`.

    Returns dictionaries containing:

        start_offset
        end_offset
        size_bytes
        chunk_count
        mean_entropy
        maximum_entropy

    This function intentionally reports regions rather than declaring them
    malicious.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    if not 0.0 <= threshold <= MAX_SHANNON_ENTROPY:
        raise ValueError("threshold must be between 0.0 and 8.0")

    if minimum_consecutive_chunks <= 0:
        raise ValueError("minimum_consecutive_chunks must be greater than zero")

    if not data:
        return []

    if isinstance(data, memoryview):
        data = data.tobytes()

    chunks = chunk_entropy(
        data,
        chunk_size=chunk_size,
        include_partial=True,
    )

    regions: list[dict[str, Any]] = []

    active_start: int | None = None
    active_entropies: list[float] = []

    for index, entropy_value in enumerate(chunks):
        is_high = entropy_value >= threshold

        if is_high:
            if active_start is None:
                active_start = index

            active_entropies.append(entropy_value)

        else:
            if active_start is not None:
                _append_entropy_region(
                    regions=regions,
                    start_chunk=active_start,
                    entropies=active_entropies,
                    chunk_size=chunk_size,
                    minimum_consecutive_chunks=minimum_consecutive_chunks,
                    data_length=len(data),
                )

                active_start = None
                active_entropies = []

    if active_start is not None:
        _append_entropy_region(
            regions=regions,
            start_chunk=active_start,
            entropies=active_entropies,
            chunk_size=chunk_size,
            minimum_consecutive_chunks=minimum_consecutive_chunks,
            data_length=len(data),
        )

    return regions


def _append_entropy_region(
    *,
    regions: list[dict[str, Any]],
    start_chunk: int,
    entropies: list[float],
    chunk_size: int,
    minimum_consecutive_chunks: int,
    data_length: int,
) -> None:
    """Append one entropy region when it satisfies the minimum length."""
    chunk_count = len(entropies)

    if chunk_count < minimum_consecutive_chunks:
        return

    start_offset = start_chunk * chunk_size
    end_offset = min(
        data_length,
        start_offset + chunk_count * chunk_size,
    )

    regions.append(
        {
            "start_offset": start_offset,
            "end_offset": end_offset,
            "size_bytes": end_offset - start_offset,
            "chunk_count": chunk_count,
            "mean_entropy": mean(entropies),
            "maximum_entropy": max(entropies),
        }
    )


# ---------------------------------------------------------------------------
# Entropy transitions
# ---------------------------------------------------------------------------


def entropy_transitions(
    data: bytes | bytearray | memoryview,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    threshold: float = ENTROPY_TRANSITION_THRESHOLD,
) -> list[dict[str, Any]]:
    """
    Locate significant entropy changes between adjacent chunks.

    Each result contains:

        left_chunk
        right_chunk
        left_offset
        right_offset
        left_entropy
        right_entropy
        absolute_difference
        direction

    `direction` is one of:

        "increase"
        "decrease"
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    if threshold < 0.0:
        raise ValueError("threshold must be >= 0.0")

    values = chunk_entropy(
        data,
        chunk_size=chunk_size,
        include_partial=True,
    )

    results: list[dict[str, Any]] = []

    for index in range(1, len(values)):
        previous = values[index - 1]
        current = values[index]

        difference = current - previous
        absolute_difference = abs(difference)

        if absolute_difference < threshold:
            continue

        results.append(
            {
                "left_chunk": index - 1,
                "right_chunk": index,
                "left_offset": (index - 1) * chunk_size,
                "right_offset": index * chunk_size,
                "left_entropy": previous,
                "right_entropy": current,
                "absolute_difference": absolute_difference,
                "direction": ("increase" if difference > 0 else "decrease"),
            }
        )

    return results


# ---------------------------------------------------------------------------
# Composite byte analysis
# ---------------------------------------------------------------------------


def analyze_bytes(
    data: bytes | bytearray | memoryview,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    window_size: int = DEFAULT_WINDOW_SIZE,
    window_step: int = DEFAULT_WINDOW_STEP,
    high_threshold: float = HIGH_ENTROPY_THRESHOLD,
    very_high_threshold: float = VERY_HIGH_ENTROPY_THRESHOLD,
    low_threshold: float = LOW_ENTROPY_THRESHOLD,
    include_distribution: bool = False,
    include_regions: bool = True,
    include_transitions: bool = True,
) -> dict[str, Any]:
    """
    Perform a complete byte-level entropy analysis.

    The default output contains scalar features suitable for feature
    engineering. Optional detailed structures can be enabled when performing
    forensic analysis or generating reports.

    The returned dictionary contains only JSON-compatible primitive values,
    lists, and dictionaries.
    """
    if isinstance(data, memoryview):
        data = data.tobytes()

    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes, bytearray, or memoryview")

    length = len(data)

    chunk_values = chunk_entropy(
        data,
        chunk_size=chunk_size,
        include_partial=True,
    )

    chunk_stats = entropy_statistics(
        chunk_values,
        high_threshold=high_threshold,
        very_high_threshold=very_high_threshold,
        low_threshold=low_threshold,
    )

    window_values = sliding_window_entropy(
        data,
        window_size=window_size,
        step=window_step,
    )

    window_stats = entropy_statistics(
        window_values,
        high_threshold=high_threshold,
        very_high_threshold=very_high_threshold,
        low_threshold=low_threshold,
    )

    features: dict[str, Any] = {
        "entropy_version": 1,
        # Basic data characteristics.
        "entropy_data_size_bytes": length,
        "entropy_empty": length == 0,
        # Whole-sample entropy.
        "entropy_shannon": shannon_entropy(data),
        "entropy_normalized": normalized_entropy(data),
        "entropy_loss": entropy_loss(data),
        # Byte distribution.
        "entropy_unique_byte_count": unique_byte_count(data),
        "entropy_byte_diversity": byte_diversity(data),
        "entropy_most_common_byte_ratio": most_common_byte_ratio(data),
        "entropy_distribution_uniformity": byte_distribution_uniformity(data),
        # Byte classes.
        "entropy_printable_ratio": printable_ratio(data),
        "entropy_ascii_ratio": ascii_ratio(data),
        "entropy_high_byte_ratio": high_byte_ratio(data),
        "entropy_null_ratio": null_byte_ratio(data),
        "entropy_control_byte_ratio": control_byte_ratio(data),
        # Chunk configuration.
        "entropy_chunk_size": chunk_size,
        "entropy_chunk_count": len(chunk_values),
        # Chunk statistics.
        "entropy_chunk_min": chunk_stats.minimum,
        "entropy_chunk_max": chunk_stats.maximum,
        "entropy_chunk_mean": chunk_stats.mean,
        "entropy_chunk_stddev": chunk_stats.standard_deviation,
        "entropy_chunk_median": chunk_stats.median,
        "entropy_chunk_high_count": chunk_stats.high_entropy_count,
        "entropy_chunk_very_high_count": (chunk_stats.very_high_entropy_count),
        "entropy_chunk_low_count": chunk_stats.low_entropy_count,
        "entropy_chunk_high_ratio": chunk_stats.high_entropy_ratio,
        "entropy_chunk_very_high_ratio": (chunk_stats.very_high_entropy_ratio),
        "entropy_chunk_low_ratio": chunk_stats.low_entropy_ratio,
        "entropy_chunk_transition_count": chunk_stats.transition_count,
        "entropy_chunk_max_transition": (chunk_stats.maximum_transition),
        # Sliding-window configuration.
        "entropy_window_size": window_size,
        "entropy_window_step": window_step,
        "entropy_window_count": len(window_values),
        # Sliding-window statistics.
        "entropy_window_min": window_stats.minimum,
        "entropy_window_max": window_stats.maximum,
        "entropy_window_mean": window_stats.mean,
        "entropy_window_stddev": window_stats.standard_deviation,
        "entropy_window_median": window_stats.median,
        "entropy_window_high_count": window_stats.high_entropy_count,
        "entropy_window_very_high_count": (window_stats.very_high_entropy_count),
        "entropy_window_low_count": window_stats.low_entropy_count,
        "entropy_window_high_ratio": window_stats.high_entropy_ratio,
        "entropy_window_very_high_ratio": (window_stats.very_high_entropy_ratio),
        "entropy_window_low_ratio": window_stats.low_entropy_ratio,
        # Coarse indicators.
        "entropy_is_high": (shannon_entropy(data) >= high_threshold),
        "entropy_is_very_high": (shannon_entropy(data) >= very_high_threshold),
        "entropy_is_low": (shannon_entropy(data) <= low_threshold),
    }

    if include_distribution:
        features["entropy_byte_frequency_distribution"] = byte_frequency_distribution(
            data
        )

    if include_regions:
        regions = high_entropy_regions(
            data,
            chunk_size=chunk_size,
            threshold=high_threshold,
        )

        features["entropy_high_regions"] = regions
        features["entropy_high_region_count"] = len(regions)

        if regions:
            features["entropy_largest_high_region_bytes"] = max(
                region["size_bytes"] for region in regions
            )
        else:
            features["entropy_largest_high_region_bytes"] = 0

    else:
        features["entropy_high_region_count"] = 0
        features["entropy_largest_high_region_bytes"] = 0

    if include_transitions:
        transitions = entropy_transitions(
            data,
            chunk_size=chunk_size,
        )

        features["entropy_transitions"] = transitions
        features["entropy_significant_transition_count"] = len(transitions)

    else:
        features["entropy_significant_transition_count"] = 0

    return _round_floats(features)


# ---------------------------------------------------------------------------
# File analysis
# ---------------------------------------------------------------------------


def _read_file_sample(
    file_path: str | os.PathLike[str],
    *,
    max_sample_size: int = DEFAULT_MAX_SAMPLE_SIZE,
) -> tuple[bytes, int]:
    """
    Read a bounded representative sample from a file.

    For files <= max_sample_size:
        Read the complete file.

    For larger files:
        Read approximately equal portions from the beginning, middle, and end.

    Returns:
        (sample_bytes, original_file_size)
    """
    if max_sample_size <= 0:
        raise ValueError("max_sample_size must be greater than zero")

    path = Path(file_path)

    try:
        file_size = path.stat().st_size
    except (OSError, ValueError) as exc:
        raise OSError(f"Unable to stat file: {path}") from exc

    if file_size <= max_sample_size:
        try:
            return path.read_bytes(), file_size
        except (OSError, ValueError) as exc:
            raise OSError(f"Unable to read file: {path}") from exc

    # Keep memory bounded while representing multiple file regions.
    beginning_size = max_sample_size // 3
    middle_size = max_sample_size // 3
    ending_size = max_sample_size - (beginning_size + middle_size)

    try:
        with path.open("rb") as handle:
            beginning = handle.read(beginning_size)

            middle_offset = max(
                0,
                (file_size // 2) - (middle_size // 2),
            )
            handle.seek(middle_offset)
            middle = handle.read(middle_size)

            ending_offset = max(
                0,
                file_size - ending_size,
            )
            handle.seek(ending_offset)
            ending = handle.read(ending_size)

    except (OSError, ValueError) as exc:
        raise OSError(f"Unable to sample file: {path}") from exc

    return beginning + middle + ending, file_size


def analyze_file(
    file_path: str | os.PathLike[str],
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    window_size: int = DEFAULT_WINDOW_SIZE,
    window_step: int = DEFAULT_WINDOW_STEP,
    max_sample_size: int = DEFAULT_MAX_SAMPLE_SIZE,
    high_threshold: float = HIGH_ENTROPY_THRESHOLD,
    very_high_threshold: float = VERY_HIGH_ENTROPY_THRESHOLD,
    low_threshold: float = LOW_ENTROPY_THRESHOLD,
    include_distribution: bool = False,
    include_regions: bool = True,
    include_transitions: bool = True,
) -> dict[str, Any]:
    """
    Analyze entropy and byte statistics for a file.

    Large files are sampled from the beginning, middle, and end to prevent
    unbounded memory consumption.

    The returned result contains:

        file size
        sample size
        sample coverage
        entropy features
        chunk statistics
        sliding-window statistics
        high-entropy regions
        entropy transitions
    """
    sample, file_size = _read_file_sample(
        file_path,
        max_sample_size=max_sample_size,
    )

    features = analyze_bytes(
        sample,
        chunk_size=chunk_size,
        window_size=window_size,
        window_step=window_step,
        high_threshold=high_threshold,
        very_high_threshold=very_high_threshold,
        low_threshold=low_threshold,
        include_distribution=include_distribution,
        include_regions=include_regions,
        include_transitions=include_transitions,
    )

    features.update(
        {
            "entropy_file_size_bytes": file_size,
            "entropy_sample_size_bytes": len(sample),
            "entropy_sample_coverage_ratio": (
                len(sample) / file_size if file_size > 0 else 0.0
            ),
            "entropy_sampling_used": file_size > max_sample_size,
            "entropy_max_sample_size": max_sample_size,
        }
    )

    return _round_floats(features)


# ---------------------------------------------------------------------------
# Feature extraction helpers
# ---------------------------------------------------------------------------


def extract_entropy_features(
    file_path: str | os.PathLike[str],
    *,
    max_sample_size: int = DEFAULT_MAX_SAMPLE_SIZE,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> dict[str, Any]:
    """
    Return only the scalar entropy features intended for ML pipelines.

    Detailed region lists, byte distributions, and transition objects are
    deliberately omitted because they are unsuitable as direct tabular
    Random Forest features.
    """
    analysis = analyze_file(
        file_path,
        max_sample_size=max_sample_size,
        chunk_size=chunk_size,
        include_distribution=False,
        include_regions=False,
        include_transitions=False,
    )

    scalar_features: dict[str, Any] = {}

    for key, value in analysis.items():
        if isinstance(value, (bool, int, float)):
            scalar_features[key] = value

    return scalar_features


def _round_floats(
    value: Any,
    *,
    digits: int = 6,
) -> Any:
    """
    Recursively round floating-point values.

    This keeps serialized feature values deterministic and prevents excessive
    floating-point representation noise in generated datasets.
    """
    if isinstance(value, float):
        return round(value, digits)

    if isinstance(value, list):
        return [_round_floats(item, digits=digits) for item in value]

    if isinstance(value, tuple):
        return tuple(_round_floats(item, digits=digits) for item in value)

    if isinstance(value, dict):
        return {key: _round_floats(item, digits=digits) for key, item in value.items()}

    return value


# ---------------------------------------------------------------------------
# Public exports
# ---------------------------------------------------------------------------

__all__ = [
    "EntropyStats",
    "shannon_entropy",
    "normalized_entropy",
    "entropy_loss",
    "byte_frequency_distribution",
    "unique_byte_count",
    "byte_diversity",
    "most_common_byte_ratio",
    "byte_distribution_uniformity",
    "printable_ratio",
    "ascii_ratio",
    "high_byte_ratio",
    "null_byte_ratio",
    "control_byte_ratio",
    "chunk_entropy",
    "sliding_window_entropy",
    "entropy_statistics",
    "high_entropy_regions",
    "entropy_transitions",
    "analyze_bytes",
    "analyze_file",
    "extract_entropy_features",
]
