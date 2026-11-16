"""
PHAROS ML - Dataset Loading Utilities
-------------------------------------
Lightweight dataset loader for reading and preparing training/evaluation matrices.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional, Sequence, Tuple

import pandas as pd

logger = logging.getLogger("ml.dataset")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_DATASET_PATH = PROJECT_ROOT / "data" / "processed" / "dataset_clean_features_40.csv"


def load_dataset(
    path: Optional[Path | str] = None,
    *,
    id_columns: Sequence[str] = ("sha256", "file_name", "hash", "id"),
    target_column: str = "label"
) -> Tuple[pd.DataFrame, pd.Series, list[str]]:
    """
    Load dataset from CSV and separate into feature matrix (X), target labels (y),
    and the list of feature column names.
    """
    data_path = Path(path) if path else DEFAULT_DATASET_PATH
    if not data_path.exists():
        raise FileNotFoundError(f"Dataset not found at {data_path}")

    df = pd.read_csv(data_path)
    
    # Exclude ID fields and target column from feature matrix
    feature_cols = [c for c in df.columns if c not in id_columns and c != target_column]

    if target_column not in df.columns:
        raise ValueError(f"Target column '{target_column}' missing from dataset {data_path}")

    X = df[feature_cols].copy()
    y = df[target_column].astype(int)

    logger.info("Loaded dataset from %s: %d samples, %d features.", data_path, len(df), len(feature_cols))
    return X, y, feature_cols


__all__ = ["load_dataset", "DEFAULT_DATASET_PATH"]
