"""
Aegis: AI-Powered Phishing Context Analyzer
Script: Ensemble ML Training (Random Forest + XGBoost)
Spec: Capstone 2 Paper Recommendation 1, Implementation Plan §6.2

Usage:
    cd aegis-backend
    python scripts/train_ensemble.py

Outputs:
    models/ensemble_rf.pkl   — trained Random Forest classifier
    models/ensemble_xgb.pkl  — trained XGBoost classifier
    scripts/train_report.txt — classification report + confusion matrix

Dataset:
    Primary:   data/benchmark_dataset.json  (if it exists with labeled samples)
    Fallback:  Synthetic balanced dataset (500 phishing + 500 legitimate)
               generated from the same heuristic feature distributions used in
               the Capstone 2 controlled evaluation.

Feature Vector (17 features — must match ensemble_classifier.py exactly):
    [url_count, ip_url_present, suspicious_tld, max_url_length,
     subdomain_depth_max, at_symbol_in_url, double_slash_redirect,
     port_in_url, urgency_keyword_count, has_typosquatting,
     body_length, subject_length, html_link_count, has_attachment,
     attachment_count, has_dangerous_ext, spf_fail]
"""

import json
import logging
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("train_ensemble")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).parent
BACKEND_DIR = SCRIPT_DIR.parent
MODELS_DIR = BACKEND_DIR / "models"
DATA_DIR = BACKEND_DIR / "data"
BENCHMARK_PATH = DATA_DIR / "benchmark_dataset.json"
REPORT_PATH = SCRIPT_DIR / "train_report.txt"

MODELS_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Dataset Loading
# ---------------------------------------------------------------------------

def _load_from_benchmark() -> tuple[np.ndarray, np.ndarray] | None:
    """
    Attempts to load labeled feature data from data/benchmark_dataset.json.

    Expected JSON format:
        [{"label": 1, "features": [f0, f1, ..., f16]}, ...]
        where label=1 is phishing, label=0 is legitimate.

    Returns (X, y) numpy arrays or None if the file is missing / wrong format.
    """
    if not BENCHMARK_PATH.exists():
        return None

    try:
        with open(BENCHMARK_PATH, encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, list) or not data:
            return None

        # Support two schemas: {label, features} dict OR {label, url, subject, ...} dict
        if "features" in data[0]:
            X = np.array([item["features"] for item in data], dtype=np.float32)
            y = np.array([item["label"] for item in data], dtype=np.int32)
            logger.info("Loaded %d labeled samples from benchmark_dataset.json", len(y))
            return X, y

    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not parse benchmark_dataset.json: %s", exc)

    return None


def _generate_synthetic_dataset() -> tuple[np.ndarray, np.ndarray]:
    """
    Generates a balanced synthetic dataset (500 phishing + 500 legitimate)
    with realistic feature distributions matching the Capstone 2 evaluation corpus.

    Phishing profile  — high urgency, typosquatting, IP URLs, dangerous attachments
    Legitimate profile — low urgency, no spoofing, normal domains
    """
    rng = np.random.default_rng(42)
    N = 500  # samples per class

    def _phishing_row() -> list[float]:
        return [
            float(rng.integers(1, 6)),                    # url_count
            float(rng.choice([0, 1], p=[0.3, 0.7])),     # ip_url_present
            float(rng.choice([0, 1], p=[0.2, 0.8])),     # suspicious_tld
            float(rng.integers(60, 300)),                  # max_url_length
            float(rng.integers(2, 6)),                     # subdomain_depth_max
            float(rng.choice([0, 1], p=[0.4, 0.6])),     # at_symbol_in_url
            float(rng.choice([0, 1], p=[0.5, 0.5])),     # double_slash_redirect
            float(rng.choice([0, 1], p=[0.6, 0.4])),     # port_in_url
            float(rng.integers(2, 8)),                     # urgency_keyword_count
            float(rng.choice([0, 1], p=[0.3, 0.7])),     # has_typosquatting
            float(rng.integers(200, 800)),                 # body_length
            float(rng.integers(20, 80)),                   # subject_length
            float(rng.integers(1, 5)),                     # html_link_count
            float(rng.choice([0, 1], p=[0.5, 0.5])),     # has_attachment
            float(rng.integers(0, 3)),                     # attachment_count
            float(rng.choice([0, 1], p=[0.4, 0.6])),     # has_dangerous_ext
            float(rng.choice([0, 1], p=[0.3, 0.7])),     # spf_fail
        ]

    def _legit_row() -> list[float]:
        return [
            float(rng.integers(0, 3)),                     # url_count
            0.0,                                           # ip_url_present
            0.0,                                           # suspicious_tld
            float(rng.integers(20, 100)),                  # max_url_length
            float(rng.integers(0, 2)),                     # subdomain_depth_max
            0.0,                                           # at_symbol_in_url
            0.0,                                           # double_slash_redirect
            0.0,                                           # port_in_url
            float(rng.integers(0, 2)),                     # urgency_keyword_count
            0.0,                                           # has_typosquatting
            float(rng.integers(50, 400)),                  # body_length
            float(rng.integers(5, 50)),                    # subject_length
            float(rng.integers(0, 3)),                     # html_link_count
            float(rng.choice([0, 1], p=[0.7, 0.3])),     # has_attachment
            float(rng.integers(0, 2)),                     # attachment_count
            0.0,                                           # has_dangerous_ext
            0.0,                                           # spf_fail
        ]

    phishing_X = np.array([_phishing_row() for _ in range(N)], dtype=np.float32)
    legit_X    = np.array([_legit_row()    for _ in range(N)], dtype=np.float32)

    X = np.vstack([phishing_X, legit_X])
    y = np.array([1] * N + [0] * N, dtype=np.int32)

    # Shuffle
    idx = rng.permutation(len(y))
    logger.info(
        "Generated synthetic dataset: %d phishing + %d legitimate = %d total",
        N, N, len(y),
    )
    return X[idx], y[idx]


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train() -> None:
    logger.info("=" * 60)
    logger.info("Aegis Ensemble ML Training — RF + XGBoost")
    logger.info("=" * 60)

    # 1. Load dataset
    result = _load_from_benchmark()
    if result is not None:
        X, y = result
        logger.info("Using benchmark dataset.")
    else:
        logger.info("benchmark_dataset.json not found or not feature-labeled. Using synthetic data.")
        X, y = _generate_synthetic_dataset()

    # 2. Train / test split (80/20, stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    logger.info(
        "Split: %d train / %d test  (positives: %d / %d)",
        len(y_train), len(y_test),
        y_train.sum(), y_test.sum(),
    )

    # 3. Random Forest
    logger.info("Training Random Forest (n_estimators=200, max_depth=12)...")
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    rf_preds = rf.predict(X_test)
    rf_f1 = f1_score(y_test, rf_preds, average="binary")
    logger.info("Random Forest — F1: %.4f", rf_f1)

    # Cross-validation
    rf_cv = cross_val_score(rf, X, y, cv=StratifiedKFold(5, shuffle=True, random_state=42), scoring="f1")
    logger.info("Random Forest — 5-Fold CV F1: %.4f ± %.4f", rf_cv.mean(), rf_cv.std())

    # 4. XGBoost
    logger.info("Training XGBoost (n_estimators=300, max_depth=6, lr=0.05)...")
    scale_pos = int((y == 0).sum()) / int((y == 1).sum())
    xgb = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )
    xgb.fit(X_train, y_train)
    xgb_preds = xgb.predict(X_test)
    xgb_f1 = f1_score(y_test, xgb_preds, average="binary")
    logger.info("XGBoost       — F1: %.4f", xgb_f1)

    xgb_cv = cross_val_score(xgb, X, y, cv=StratifiedKFold(5, shuffle=True, random_state=42), scoring="f1")
    logger.info("XGBoost       — 5-Fold CV F1: %.4f ± %.4f", xgb_cv.mean(), xgb_cv.std())

    # 5. Save models
    rf_path = MODELS_DIR / "ensemble_rf.pkl"
    xgb_path = MODELS_DIR / "ensemble_xgb.pkl"
    joblib.dump(rf, rf_path)
    joblib.dump(xgb, xgb_path)
    logger.info("Saved: %s", rf_path)
    logger.info("Saved: %s", xgb_path)

    # 6. Save text report
    report_lines = [
        "Aegis Ensemble ML Training Report",
        "=" * 60,
        "",
        f"Dataset size: {len(y)} samples ({int(y.sum())} phishing / {int((y==0).sum())} legitimate)",
        f"Train/Test split: {len(y_train)} / {len(y_test)}",
        "",
        "--- Random Forest ---",
        f"Test F1: {rf_f1:.4f}",
        f"5-Fold CV F1: {rf_cv.mean():.4f} ± {rf_cv.std():.4f}",
        "",
        "Classification Report (RF):",
        classification_report(y_test, rf_preds, target_names=["Legitimate", "Phishing"]),
        "",
        "Confusion Matrix (RF):",
        str(confusion_matrix(y_test, rf_preds)),
        "",
        "--- XGBoost ---",
        f"Test F1: {xgb_f1:.4f}",
        f"5-Fold CV F1: {xgb_cv.mean():.4f} ± {xgb_cv.std():.4f}",
        "",
        "Classification Report (XGB):",
        classification_report(y_test, xgb_preds, target_names=["Legitimate", "Phishing"]),
        "",
        "Confusion Matrix (XGB):",
        str(confusion_matrix(y_test, xgb_preds)),
        "",
        "Feature Importance (RF — top 10):",
    ]
    importances = rf.feature_importances_
    feat_names = [
        "url_count", "ip_url_present", "suspicious_tld", "max_url_length",
        "subdomain_depth_max", "at_symbol_in_url", "double_slash_redirect",
        "port_in_url", "urgency_keyword_count", "has_typosquatting",
        "body_length", "subject_length", "html_link_count", "has_attachment",
        "attachment_count", "has_dangerous_ext", "spf_fail",
    ]
    sorted_idx = np.argsort(importances)[::-1]
    for rank, idx in enumerate(sorted_idx[:10], 1):
        report_lines.append(f"  {rank:2d}. {feat_names[idx]:<30s} {importances[idx]:.4f}")

    report_text = "\n".join(report_lines)
    REPORT_PATH.write_text(report_text, encoding="utf-8")
    logger.info("Report saved: %s", REPORT_PATH)

    logger.info("")
    logger.info("=" * 60)
    logger.info("Training complete.")
    logger.info("  RF  F1: %.4f  |  XGB F1: %.4f", rf_f1, xgb_f1)
    logger.info("Models saved to: %s", MODELS_DIR)
    logger.info("=" * 60)


if __name__ == "__main__":
    try:
        train()
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
        sys.exit(0)
