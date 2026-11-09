"""
Calibration of the Warning Cut-Off on the 200-Email TRAIN Split ONLY
Ground-truth empirical script for Aegis Phishing Context Analyzer.
Evaluates the 200-sample train split (E-39_dataset_train_200.csv) to determine
an empirically calibrated Warning tier threshold.
Generator: claude.ai
"""

import sys
import os
import csv
import json
from pathlib import Path
import numpy as np

# Adjust path to find repo root
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "aegis-backend"))

from run_round2_evaluations import evaluate_sample_pipeline, calc_metrics, wilson_ci
from modules.nlp_classifier import warm_up_nlp, is_model_warm, get_model_id

def main():
    warm_up_nlp()
    if not is_model_warm():
        print("FATAL: DistilBERT model reports warm=False. Evaluation harness aborted.")
        sys.exit(1)
    print(f"DistilBERT Warm: {is_model_warm()} | Model ID: {get_model_id()}")
    train_csv = REPO_ROOT / "evidence" / "E-39_independent-corpus" / "E-39_dataset_train_200.csv"
    if not train_csv.exists():
        print(f"Error: {train_csv} does not exist.")
        sys.exit(1)

    with open(train_csv, "r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    print(f"Loaded {len(rows)} emails from TRAIN split.")

    phish_scores = []
    legit_scores = []
    records = []

    for r in rows:
        lbl = int(r["label"])
        res = evaluate_sample_pipeline(r, config="full")
        sc = res["score"]
        if lbl == 1:
            phish_scores.append(sc)
        else:
            legit_scores.append(sc)
        records.append({
            "id": r["id"],
            "label": lbl,
            "score": sc,
            "pred": res,
        })

    print(f"Phishing (N={len(phish_scores)}): min={min(phish_scores)}, max={max(phish_scores)}, mean={np.mean(phish_scores):.2f}, median={np.median(phish_scores)}")
    print(f"Legitimate (N={len(legit_scores)}): min={min(legit_scores)}, max={max(legit_scores)}, mean={np.mean(legit_scores):.2f}, median={np.median(legit_scores)}")

    max_legit_score = max(legit_scores)
    print(f"\nHighest legitimate score observed on TRAIN: {max_legit_score}")
    print(f"Legitimate scores frequency distribution: {dict(zip(*np.unique(legit_scores, return_counts=True)))}")

    print("\n--- TRAIN SWEEP (Thresholds 10 to 60) ---")
    header = f"{'Thresh':>6} | {'TP':>3} | {'FP':>3} | {'TN':>3} | {'FN':>3} | {'Recall (%)':>10} | {'FPR (%)':>8} | {'Prec (%)':>9} | {'F1 (%)':>7} | {'Accuracy (%)':>12} | {'Youden J':>8}"
    print(header)
    print("-" * len(header))

    best_j = -1.0
    best_j_thresh = None
    best_f1 = -1.0
    best_f1_thresh = None
    zero_fpr_thresh = None
    zero_fpr_recall = -1.0

    sweep_results = []

    for t in range(10, 61):
        y_true = [rec["label"] for rec in records]
        y_pred = [1 if rec["score"] >= t else 0 for rec in records]
        scores = [rec["score"] for rec in records]
        m = calc_metrics(y_true, y_pred, scores)
        # Recall and FPR in calc_metrics are in 0-100 range
        rec_frac = m["recall"] / 100.0
        fpr_frac = m["fpr"] / 100.0
        j = rec_frac - fpr_frac

        sweep_results.append({
            "threshold": t,
            "metrics": m,
            "youden_j": round(j, 4),
        })

        if j > best_j:
            best_j = j
            best_j_thresh = t

        if m["f1_score"] > best_f1:
            best_f1 = m["f1_score"]
            best_f1_thresh = t

        if m["fpr"] == 0.0 and m["recall"] > zero_fpr_recall:
            zero_fpr_recall = m["recall"]
            zero_fpr_thresh = t

        if t in range(15, 55, 2) or t in [best_j_thresh, best_f1_thresh, zero_fpr_thresh, 45]:
            print(f"{t:6d} | {m['tp']:3d} | {m['fp']:3d} | {m['tn']:3d} | {m['fn']:3d} | {m['recall']:9.2f}% | {m['fpr']:7.2f}% | {m['precision']:8.2f}% | {m['f1_score']:6.2f}% | {m['accuracy']:11.2f}% | {j:8.4f}")

    print("\n--- SELECTION CRITERIA SUMMARY ON TRAIN ---")
    print(f"1. Maximum Youden's J: Threshold = {best_j_thresh} (J = {best_j:.4f}, Recall = {sweep_results[best_j_thresh-10]['metrics']['recall']:.2f}%, FPR = {sweep_results[best_j_thresh-10]['metrics']['fpr']:.2f}%)")
    print(f"2. Maximum F1-Score:    Threshold = {best_f1_thresh} (F1 = {best_f1:.2f}%, Recall = {sweep_results[best_f1_thresh-10]['metrics']['recall']:.2f}%, FPR = {sweep_results[best_f1_thresh-10]['metrics']['fpr']:.2f}%)")
    print(f"3. Strict Zero-FPR (FPR=0.0%): Threshold = {zero_fpr_thresh} (Recall = {zero_fpr_recall:.2f}%, Accuracy = {sweep_results[zero_fpr_thresh-10]['metrics']['accuracy']:.2f}%)")

    # Output detailed report to evidence/E-39_independent-corpus/E-39_train_calibration_report.json
    out_dir = REPO_ROOT / "evidence" / "E-39_independent-corpus"
    report = {
        "generator": "claude.ai",
        "model_name": "claude.ai",
        "model_loaded": is_model_warm(),
        "model_id": get_model_id(),
        "train_samples_total": len(rows),
        "train_phishing_count": len(phish_scores),
        "train_legitimate_count": len(legit_scores),
        "phishing_scores": {
            "min": int(min(phish_scores)),
            "max": int(max(phish_scores)),
            "mean": float(np.mean(phish_scores)),
            "median": float(np.median(phish_scores)),
        },
        "legitimate_scores": {
            "min": int(min(legit_scores)),
            "max": int(max(legit_scores)),
            "mean": float(np.mean(legit_scores)),
            "median": float(np.median(legit_scores)),
        },
        "max_legitimate_score_zero_fpr_boundary": int(max_legit_score),
        "calibrated_candidates": {
            "max_youden_j": {
                "threshold": best_j_thresh,
                "metrics": sweep_results[best_j_thresh-10]["metrics"],
                "youden_j": best_j,
            },
            "max_f1": {
                "threshold": best_f1_thresh,
                "metrics": sweep_results[best_f1_thresh-10]["metrics"],
            },
            "zero_fpr_optimal": {
                "threshold": zero_fpr_thresh,
                "metrics": sweep_results[zero_fpr_thresh-10]["metrics"],
            },
        },
        "all_sweep_results": sweep_results,
    }

    with open(out_dir / "E-39_train_calibration_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\nSaved calibration report to: {out_dir / 'E-39_train_calibration_report.json'}")

if __name__ == "__main__":
    main()
