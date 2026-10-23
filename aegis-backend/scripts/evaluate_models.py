"""
Aegis: AI-Powered Phishing Context Analyzer
Script: Model Evaluation & Performance Metrics (PR-08)
Spec: Capstone 2 Paper §4.2, Table 16 — Model Evaluation Protocol

Usage:
    # Step 1: Prepare test dataset
    cd aegis-backend
    python scripts/prepare_test_dataset.py --size 200

    # Step 2: Start the backend in a separate terminal
    uvicorn main:app --port 8000

    # Step 3: Run evaluation (backend must be running)
    python scripts/evaluate_models.py

    # Or run offline (skips live API, uses local layer evaluation only):
    python scripts/evaluate_models.py --offline

Outputs:
    results/evaluation_report.json   — Full machine-readable metrics report
    results/evaluation_report.txt    — Human-readable formatted table (for paper)
    results/confusion_matrix.txt     — ASCII confusion matrix for all tiers

Metrics computed (per paper Table 16):
    - Accuracy    = (TP + TN) / total
    - Precision   = TP / (TP + FP)
    - Recall      = TP / (TP + FN)
    - F1-Score    = 2 * (P * R) / (P + R)
    - FPR         = FP / (FP + TN)  — False Positive Rate
    - Avg Latency — mean response time per email (ms)
    - p50 / p95 / p99 latency percentiles

Comparison baselines referenced in paper (Table 16):
    Gmail:    Accuracy 82.3%, FPR 4.1%
    Outlook:  Accuracy 79.8%, FPR 5.8%
    Yahoo:    Accuracy 76.4%, FPR 7.2%
    Aegis:    Target ≥ 94.0% accuracy, ≤ 2.0% FPR
"""

import argparse
import csv
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("evaluate_models")

SCRIPT_DIR  = Path(__file__).parent
BACKEND_DIR = SCRIPT_DIR.parent
DATA_DIR    = BACKEND_DIR / "data"
RESULTS_DIR = BACKEND_DIR / "results"

# Risk tier thresholds (must match meta_classifier.py)
TIER_SAFE_MAX    = 44
TIER_WARNING_MAX = 74
# Score >= 75 → Critical

# For binary classification: Safe = Legitimate, Warning/Critical = Phishing
PHISHING_SCORE_THRESHOLD = TIER_SAFE_MAX + 1  # score >= 45 → predicted phishing


# ---------------------------------------------------------------------------
# Comparison baselines from paper (Table 16)
# ---------------------------------------------------------------------------
BASELINES = {
    "Gmail":    {"accuracy": 82.3, "precision": 83.1, "recall": 80.7, "f1": 81.9, "fpr": 4.1},
    "Outlook":  {"accuracy": 79.8, "precision": 80.2, "recall": 78.1, "f1": 79.1, "fpr": 5.8},
    "Yahoo":    {"accuracy": 76.4, "precision": 77.0, "recall": 75.2, "f1": 76.1, "fpr": 7.2},
    "Proton":   {"accuracy": 74.1, "precision": 74.8, "recall": 72.9, "f1": 73.8, "fpr": 8.4},
}


# ---------------------------------------------------------------------------
# Offline local evaluation (no live API — uses backend modules directly)
# ---------------------------------------------------------------------------

def _local_evaluate_sample(row: Dict[str, Any], neutral_auth: bool = False) -> Tuple[int, float]:
    """
    Runs a single sample through Layers 1-3 locally (no network call).
    Returns (predicted_label, score, elapsed_ms).
    Layer 4 (VirusTotal) is skipped in offline mode.
    """
    import importlib
    import sys
    import os

    # Ensure backend modules are importable
    backend_path = str(BACKEND_DIR)
    if backend_path not in sys.path:
        sys.path.insert(0, backend_path)

    from routes.analyze import (
        EmailPayload, evaluate_layer1, evaluate_nlp_intent,
        evaluate_behavioral, extract_url_strings,
    )
    from modules.meta_classifier import synthesize_composite_score

    import json as _json

    links_raw = row.get("links", "[]")
    try:
        links = _json.loads(links_raw) if isinstance(links_raw, str) else links_raw
    except Exception:
        links = []

    attachments_raw = row.get("attachments", "[]")
    try:
        attachments = _json.loads(attachments_raw) if isinstance(attachments_raw, str) else attachments_raw
    except Exception:
        attachments = []

    if neutral_auth:
        spf_pass = True
        dkim_pass = True
    else:
        spf_raw  = row.get("spfPass", "True")
        dkim_raw = row.get("dkimPass", "True")
        spf_pass  = spf_raw  if isinstance(spf_raw,  bool) else str(spf_raw).lower()  == "true"
        dkim_pass = dkim_raw if isinstance(dkim_raw, bool) else str(dkim_raw).lower() == "true"

    payload = EmailPayload(
        senderEmail     = row.get("senderEmail", ""),
        subject         = row.get("subject", ""),
        bodyText        = row.get("bodyText", ""),
        links           = links,
        attachments     = attachments,
        hasAttachment   = bool(attachments),
        attachmentCount = len(attachments),
        spfPass         = spf_pass,
        dkimPass        = dkim_pass,
    )

    t_start = time.time()
    urls       = extract_url_strings(payload.links or [])
    layer1     = evaluate_layer1(payload, urls)
    s_heuristic = layer1["score"]
    s_nlp       = evaluate_nlp_intent(payload, layer1["keyword_hits"], layer1.get("has_typosquatting", False))
    s_behavioral = evaluate_behavioral(payload)
    score = synthesize_composite_score(
        s_heuristic=s_heuristic,
        s_nlp=s_nlp,
        s_behavioral=s_behavioral,
        s_vt=0,
        vt_pending=True,
    )
    elapsed_ms = (time.time() - t_start) * 1000
    return score, elapsed_ms


def _api_evaluate_sample(row: Dict[str, Any], base_url: str, neutral_auth: bool = False) -> Tuple[int, float]:
    """Calls the live /api/v1/analyze endpoint for a single sample."""
    import urllib.request
    import json as _json

    links_raw = row.get("links", "[]")
    try:
        links = _json.loads(links_raw) if isinstance(links_raw, str) else links_raw
    except Exception:
        links = []

    attachments_raw = row.get("attachments", "[]")
    try:
        attachments = _json.loads(attachments_raw) if isinstance(attachments_raw, str) else attachments_raw
    except Exception:
        attachments = []

    if neutral_auth:
        spf_val = True
        dkim_val = True
    else:
        spf_raw  = row.get("spfPass", "True")
        dkim_raw = row.get("dkimPass", "True")
        spf_val = str(spf_raw).lower() == "true"
        dkim_val = str(dkim_raw).lower() == "true"

    payload_dict = {
        "senderEmail":     row.get("senderEmail", ""),
        "subject":         row.get("subject", ""),
        "bodyText":        row.get("bodyText", ""),
        "links":           links,
        "attachments":     attachments,
        "hasAttachment":   bool(attachments),
        "attachmentCount": len(attachments),
        "spfPass":         spf_val,
        "dkimPass":        dkim_val,
    }

    req_body = _json.dumps(payload_dict).encode("utf-8")
    url = f"{base_url.rstrip('/')}/api/v1/analyze"

    t_start = time.time()
    req = urllib.request.Request(
        url,
        data=req_body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        result = _json.loads(resp.read())
    elapsed_ms = (time.time() - t_start) * 1000
    score = result.get("score", 0)
    return score, elapsed_ms


# ---------------------------------------------------------------------------
# Metrics computation
# ---------------------------------------------------------------------------

def compute_metrics(
    true_labels: List[int],
    pred_labels: List[int],
    latencies_ms: List[float],
) -> Dict[str, Any]:
    """Computes all evaluation metrics referenced in Capstone 2 paper Table 16."""
    n = len(true_labels)
    if n == 0:
        return {}

    tp = sum(1 for t, p in zip(true_labels, pred_labels) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(true_labels, pred_labels) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(true_labels, pred_labels) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(true_labels, pred_labels) if t == 1 and p == 0)

    accuracy  = (tp + tn) / n * 100
    precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr       = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0.0
    fnr       = fn / (fn + tp) * 100 if (fn + tp) > 0 else 0.0

    # Latency percentiles
    sorted_lat = sorted(latencies_ms)
    def pct(data, p):
        if not data: return 0.0
        idx = max(0, int(len(data) * p / 100) - 1)
        return data[idx]

    return {
        "total_samples": n,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy":       round(accuracy, 2),
        "precision":      round(precision, 2),
        "recall":         round(recall, 2),
        "f1_score":       round(f1, 2),
        "fpr":            round(fpr, 2),
        "fnr":            round(fnr, 2),
        "latency_avg_ms": round(sum(latencies_ms) / len(latencies_ms), 2),
        "latency_p50_ms": round(pct(sorted_lat, 50), 2),
        "latency_p95_ms": round(pct(sorted_lat, 95), 2),
        "latency_p99_ms": round(pct(sorted_lat, 99), 2),
    }


def build_confusion_matrix_ascii(tp: int, tn: int, fp: int, fn: int) -> str:
    """Renders a readable ASCII confusion matrix."""
    lines = [
        "",
        "  Confusion Matrix (Rows=Actual, Cols=Predicted)",
        "  +-----------------+------------+------------+",
        "  |                 | Pred. SAFE | Pred. PHSH |",
        "  +-----------------+------------+------------+",
        f"  | Actual LEGIT    |  TN={tn:>5}  |  FP={fp:>5}  |",
        f"  | Actual PHISHING |  FN={fn:>5}  |  TP={tp:>5}  |",
        "  +-----------------+------------+------------+",
        "",
    ]
    return "\n".join(lines)


def format_report(metrics: Dict[str, Any], mode: str, dataset_path: str) -> str:
    """Formats the evaluation report as a readable table for the paper."""
    m = metrics
    sep = "=" * 65
    sub_sep = "-" * 57
    lines = [
        sep,
        "  AEGIS PHISHING ANALYZER -- MODEL EVALUATION REPORT (PR-08)",
        sep,
        f"  Mode:           {mode}",
        f"  Dataset:        {dataset_path}",
        f"  Total Samples:  {m['total_samples']} ({m['tp']+m['fn']} phishing / {m['tn']+m['fp']} legitimate)",
        "",
        "  --- Classification Metrics --------------------------------",
        f"  Accuracy:       {m['accuracy']:>6.2f}%",
        f"  Precision:      {m['precision']:>6.2f}%",
        f"  Recall:         {m['recall']:>6.2f}%",
        f"  F1-Score:       {m['f1_score']:>6.2f}%",
        f"  False Pos Rate: {m['fpr']:>6.2f}%",
        f"  False Neg Rate: {m['fnr']:>6.2f}%",
        "",
        "  --- Response Latency --------------------------------------",
        f"  Average:        {m['latency_avg_ms']:>7.1f} ms",
        f"  p50 (median):   {m['latency_p50_ms']:>7.1f} ms",
        f"  p95:            {m['latency_p95_ms']:>7.1f} ms",
        f"  p99:            {m['latency_p99_ms']:>7.1f} ms",
        "",
        "  --- Comparison vs. Baseline Email Clients -----------------",
        f"  {'System':<14} {'Accuracy':>9} {'Precision':>10} {'Recall':>8} {'F1':>6} {'FPR':>6}",
        "  " + sub_sep,
    ]
    for name, b in BASELINES.items():
        lines.append(
            f"  {name:<14} {b['accuracy']:>8.1f}% {b['precision']:>9.1f}%"
            f" {b['recall']:>7.1f}% {b['f1']:>5.1f}% {b['fpr']:>5.1f}%"
        )
    # Aegis row
    lines.append(
        f"  {'Aegis (this)':<14} {m['accuracy']:>8.2f}% {m['precision']:>9.2f}%"
        f" {m['recall']:>7.2f}% {m['f1_score']:>5.2f}% {m['fpr']:>5.2f}%"
    )
    lines += [
        "",
        build_confusion_matrix_ascii(m["tp"], m["tn"], m["fp"], m["fn"]),
        sep,
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Aegis Model Evaluation Script (PR-08)"
    )
    parser.add_argument(
        "--dataset", type=str,
        default=str(DATA_DIR / "test_dataset.csv"),
        help="Path to labeled test dataset CSV (default: data/test_dataset.csv)"
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="Run offline evaluation using local pipeline (no live backend required)"
    )
    parser.add_argument(
        "--backend-url", type=str, default="http://localhost:8000",
        help="Backend base URL for live API evaluation (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--output-dir", type=str, default=str(RESULTS_DIR),
        help="Directory for evaluation output files (default: results/)"
    )
    parser.add_argument(
        "--neutral-auth", action="store_true",
        help="Force neutral authentication flags (spfPass=True, dkimPass=True) to eliminate synthetic auth label leakage"
    )
    parser.add_argument(
        "--export-samples", type=str, default="",
        help="Path to export per-sample results CSV (default: <output-dir>/per_sample_evaluation.csv)"
    )
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        logger.error(
            "Test dataset not found: %s\n"
            "Run: python scripts/prepare_test_dataset.py first.",
            dataset_path,
        )
        sys.exit(1)

    # Load dataset
    rows = []
    with open(dataset_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    logger.info("Loaded %d samples from %s", len(rows), dataset_path)
    auth_label = "NEUTRAL AUTH (spfPass=True, dkimPass=True)" if args.neutral_auth else "SYNTHETIC AUTH (from dataset)"
    mode = ("OFFLINE (local pipeline, VT skipped)" if args.offline else f"LIVE API ({args.backend_url})") + f" | {auth_label}"
    logger.info("Evaluation mode: %s", mode)

    true_labels: List[int] = []
    pred_labels: List[int] = []
    latencies:   List[float] = []
    sample_records: List[Dict[str, Any]] = []
    errors = 0

    for i, row in enumerate(rows):
        true_label = int(row.get("label", 0))
        try:
            if args.offline:
                score, elapsed = _local_evaluate_sample(row, neutral_auth=args.neutral_auth)
            else:
                score, elapsed = _api_evaluate_sample(row, args.backend_url, neutral_auth=args.neutral_auth)

            pred_label = 1 if score >= PHISHING_SCORE_THRESHOLD else 0
            true_labels.append(true_label)
            pred_labels.append(pred_label)
            latencies.append(elapsed)

            sample_records.append({
                "id": row.get("id", i),
                "label": true_label,
                "label_name": row.get("label_name", "Phishing" if true_label else "Legitimate"),
                "senderEmail": row.get("senderEmail", ""),
                "subject": row.get("subject", ""),
                "score": score,
                "pred_label": pred_label,
                "pred_name": "Phishing" if pred_label else "Safe",
                "result": "CORRECT" if pred_label == true_label else "ERROR",
                "elapsed_ms": round(elapsed, 2),
                "auth_mode": "neutral" if args.neutral_auth else "synthetic",
            })

            if (i + 1) % 20 == 0:
                correct_so_far = sum(t == p for t, p in zip(true_labels, pred_labels))
                logger.info(
                    "[%d/%d] score=%d pred=%s true=%s | acc_so_far=%.1f%% | lat=%.1fms",
                    i + 1, len(rows), score,
                    "Phishing" if pred_label else "Legit",
                    "Phishing" if true_label else "Legit",
                    correct_so_far / len(true_labels) * 100,
                    elapsed,
                )
        except Exception as exc:
            logger.warning("Sample %d failed: %s", i, exc)
            errors += 1
            continue

    if not true_labels:
        logger.error("No samples evaluated successfully. Check backend connectivity or dataset.")
        sys.exit(1)

    if errors:
        logger.warning("%d samples failed and were skipped.", errors)

    # Compute metrics
    metrics = compute_metrics(true_labels, pred_labels, latencies)
    metrics["evaluation_mode"] = "offline" if args.offline else "live_api"
    metrics["auth_mode"]       = "neutral" if args.neutral_auth else "synthetic"
    metrics["backend_url"]     = args.backend_url if not args.offline else "N/A"
    metrics["dataset_path"]    = str(dataset_path)
    metrics["errors_skipped"]  = errors
    metrics["baselines"]       = BASELINES

    # Write outputs
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    report_json = output_dir / ("evaluation_report_neutral.json" if args.neutral_auth else "evaluation_report.json")
    report_txt  = output_dir / ("evaluation_report_neutral.txt" if args.neutral_auth else "evaluation_report.txt")
    matrix_txt  = output_dir / ("confusion_matrix_neutral.txt" if args.neutral_auth else "confusion_matrix.txt")
    export_csv  = Path(args.export_samples) if args.export_samples else (output_dir / ("per_sample_evaluation_neutral.csv" if args.neutral_auth else "per_sample_evaluation.csv"))

    with open(report_json, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    report_str = format_report(metrics, mode, str(dataset_path))
    with open(report_txt, "w", encoding="utf-8") as f:
        f.write(report_str)

    matrix_str = build_confusion_matrix_ascii(
        metrics["tp"], metrics["tn"], metrics["fp"], metrics["fn"]
    )
    with open(matrix_txt, "w", encoding="utf-8") as f:
        f.write(matrix_str)

    if sample_records:
        fieldnames = ["id", "label", "label_name", "senderEmail", "subject", "score", "pred_label", "pred_name", "result", "elapsed_ms", "auth_mode"]
        with open(export_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(sample_records)
        logger.info("Per-sample CSV written to: %s", export_csv)

    # Print to console
    print("\n" + report_str)
    logger.info("Reports written to: %s", output_dir)
    logger.info("  %s", report_json.name)
    logger.info("  %s", report_txt.name)
    logger.info("  %s", matrix_txt.name)


if __name__ == "__main__":
    main()
