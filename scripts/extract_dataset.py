"""
Build a machine-learning dataset from files in data/raw/{benign,malicious}.

The feature extraction itself is handled by FeaturePipeline. This script only:
- discovers input files
- assigns labels from the parent directory
- skips files already processed successfully
- extracts numeric features
- writes the dataset incrementally
- keeps a small persistent processing state
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
from pathlib import Path
from typing import Iterable

from src.extraction.feature_pipeline import FeaturePipeline

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = PROJECT_ROOT / "data" / "raw"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"

DATASET_FILE = PROCESSED_DIR / "dataset.csv"
STATE_FILE = PROCESSED_DIR / "processed.json"

LABELS = {
    "benign": 0,
    "malicious": 1,
}

LOG = logging.getLogger("extract_dataset")


def discover_files() -> Iterable[tuple[Path, int]]:
    """Yield supported dataset files and their labels."""
    for name, label in LABELS.items():
        directory = RAW_DIR / name

        if not directory.exists():
            LOG.warning("Directory not found: %s", directory)
            continue

        for path in directory.rglob("*"):
            if path.is_file():
                yield path, label


def file_hash(path: Path) -> str:
    """Return the SHA-256 hash of a file."""
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def load_state() -> dict[str, dict]:
    """Load successfully processed files."""
    if not STATE_FILE.exists():
        return {}

    try:
        with STATE_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)

        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        LOG.warning("Could not read processing state. Starting fresh.")
        return {}


def save_state(state: dict[str, dict]) -> None:
    """Persist processing state."""
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    temporary = STATE_FILE.with_suffix(".tmp")

    with temporary.open("w", encoding="utf-8") as file:
        json.dump(state, file, separators=(",", ":"))

    temporary.replace(STATE_FILE)


def load_existing_columns() -> list[str]:
    """Return existing dataset columns, if the dataset already exists."""
    if not DATASET_FILE.exists():
        return []

    try:
        with DATASET_FILE.open("r", encoding="utf-8", newline="") as file:
            return next(csv.reader(file), [])
    except (OSError, StopIteration):
        return []


def write_row(row: dict[str, object], columns: list[str]) -> None:
    """Append one dataset row."""
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    new_file = not DATASET_FILE.exists()

    with DATASET_FILE.open("a", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=columns,
            extrasaction="ignore",
        )

        if new_file:
            writer.writeheader()

        writer.writerow(row)


def extract_file(
    pipeline: FeaturePipeline,
    path: Path,
    label: int,
) -> tuple[dict[str, object], str]:
    """Extract one file and return its dataset row and content hash."""
    result = pipeline.analyze_file(path)
    sha256 = result.source_hash or file_hash(path)

    row = {
        "sha256": sha256,
        "label": label,
        **result.feature_vector,
    }

    return row, sha256


def build_dataset(force: bool = False) -> None:
    """Extract all unprocessed files into the dataset."""
    state = {} if force else load_state()
    pipeline = FeaturePipeline()

    columns = load_existing_columns()
    processed = skipped = failed = 0

    for path, label in discover_files():
        try:
            sha256 = file_hash(path)

            if not force and sha256 in state:
                skipped += 1
                continue

            row, sha256 = extract_file(pipeline, path, label)

            if not columns:
                columns = list(row)

            missing = [name for name in row if name not in columns]

            if missing:
                raise ValueError(f"New feature columns detected: {', '.join(missing)}")

            write_row(row, columns)

            state[sha256] = {
                "label": label,
                "path": str(path.relative_to(PROJECT_ROOT)),
            }

            save_state(state)
            processed += 1

            LOG.info("Processed: %s", path)

        except Exception as exc:
            failed += 1
            LOG.error("Could not parse %s: %s", path, exc)

    LOG.info(
        "Dataset extraction complete: processed=%d skipped=%d failed=%d",
        processed,
        skipped,
        failed,
    )


def extract_one(path: Path, label: int) -> None:
    """Extract a single file."""
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    pipeline = FeaturePipeline()
    row, _ = extract_file(pipeline, path, label)

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    columns = list(row)

    with DATASET_FILE.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerow(row)

    LOG.info("Extracted: %s", path)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build the malware detection feature dataset."
    )

    parser.add_argument(
        "--file",
        type=Path,
        help="Extract features from a single file.",
    )

    parser.add_argument(
        "--label",
        choices=LABELS,
        help="Label for --file.",
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="Reprocess files already present in the processing state.",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed logging.",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    if args.file:
        if not args.label:
            parser.error("--label is required with --file")

        extract_one(args.file, LABELS[args.label])
        return

    build_dataset(force=args.force)


if __name__ == "__main__":
    main()
