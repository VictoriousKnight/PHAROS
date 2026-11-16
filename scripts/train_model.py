#!/usr/bin/env python3
"""
PHAROS CDR - Train Model Script
Usage:
    python scripts/train_model.py
    python scripts/train_model.py --dataset data/processed/dataset_clean_features_40.csv --trees 200
"""

import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, f1_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("train_model")

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def parse_args():
    parser = argparse.ArgumentParser(
        description="Train PHAROS Random Forest Classifier"
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=PROJECT_ROOT / "data/processed/dataset_clean_features_40.csv",
    )
    parser.add_argument(
        "--output-model",
        type=Path,
        default=PROJECT_ROOT / "models/trained/random_forest.joblib",
    )
    parser.add_argument(
        "--output-meta",
        type=Path,
        default=PROJECT_ROOT / "models/metadata/model_metadata.json",
    )
    parser.add_argument(
        "--output-schema",
        type=Path,
        default=PROJECT_ROOT / "models/metadata/feature_schema.json",
    )
    parser.add_argument("--test-size", type=float, default=0.20)
    parser.add_argument("--trees", type=int, default=200)
    parser.add_argument("--random-state", type=int, default=42)
    return parser.parse_args()


def main():
    args = parse_args()
    logger.info(f"Loading training data from: {args.dataset}")
    df = pd.read_csv(args.dataset)

    # Separate identifier, target label, and features
    id_cols = [c for c in ["sha256", "file_name", "hash", "id"] if c in df.columns]
    feature_cols = [c for c in df.columns if c not in id_cols and c != "label"]

    X = df[feature_cols].copy()
    y = df["label"].astype(int).values

    logger.info(f"Loaded {len(df)} samples with {len(feature_cols)} features.")

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.random_state, stratify=y
    )

    # Standard model pipeline: Imputation -> Scaled/Trees Classifier
    pipeline = Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median")),
            (
                "model",
                RandomForestClassifier(
                    n_estimators=args.trees,
                    max_depth=16,
                    min_samples_split=4,
                    min_samples_leaf=2,
                    class_weight="balanced",
                    random_state=args.random_state,
                    n_jobs=-1,
                ),
            ),
        ]
    )

    # 5-Fold Stratified Cross-Validation
    logger.info("Executing 5-Fold Stratified Cross-Validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=args.random_state)
    cv_auc = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring="roc_auc")
    cv_f1 = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring="f1")
    logger.info(
        f"5-Fold CV ROC-AUC: {cv_auc.mean():.4f} (+/- {cv_auc.std():.4f}) | F1: {cv_f1.mean():.4f}"
    )

    # Final Fit on Training Set
    logger.info("Fitting final model...")
    pipeline.fit(X_train, y_train)

    # Evaluate on held-out test split
    test_probs = pipeline.predict_proba(X_test)[:, 1]
    test_preds = (test_probs >= 0.5).astype(int)
    test_auc = roc_auc_score(y_test, test_probs)
    test_f1 = f1_score(y_test, test_preds)
    logger.info(f"Held-out Test ROC-AUC: {test_auc:.4f} | F1: {test_f1:.4f}")
    print("\n" + classification_report(y_test, test_preds, digits=4))

    # Save artifacts
    args.output_model.parent.mkdir(parents=True, exist_ok=True)
    args.output_meta.parent.mkdir(parents=True, exist_ok=True)

    # Save standalone estimator & pipeline
    rf_clf = pipeline.named_steps["model"]
    joblib.dump(rf_clf, args.output_model)
    pipeline_path = args.output_model.parent / "trained_model_pipeline.joblib"
    joblib.dump(pipeline, pipeline_path)
    logger.info(f"Models saved: {args.output_model} and {pipeline_path}")

    # Save Model Metadata
    metadata = {
        "model_name": "RandomForestClassifier",
        "version": "2.0.0",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "n_samples": len(df),
        "n_features": len(feature_cols),
        "features": feature_cols,
        "best_parameters": rf_clf.get_params(),
        "metrics": {
            "cv_roc_auc_mean": float(cv_auc.mean()),
            "cv_f1_mean": float(cv_f1.mean()),
            "test_roc_auc": float(test_auc),
            "test_f1": float(test_f1),
        },
        "decision_thresholds": {"strict": 0.35, "balanced": 0.50, "high_recall": 0.65},
    }
    with open(args.output_meta, "w") as f:
        json.dump(metadata, f, indent=2)

    # Save Feature Schema
    schema = {
        "schema_version": "2.0.0",
        "features": feature_cols,
        "label_name": "label",
        "id_fields": id_cols,
    }
    with open(args.output_schema, "w") as f:
        json.dump(schema, f, indent=2)

    logger.info(f"Metadata and feature schema saved to {args.output_meta.parent}")


if __name__ == "__main__":
    main()
