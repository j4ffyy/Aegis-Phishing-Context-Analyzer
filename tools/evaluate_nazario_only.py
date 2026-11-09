"""
Evaluate Pure Jose Nazario Phishing (125 samples) vs Public Ham
Seed 42 80/20 holdout test split (N=50: 25 pure Nazario, 25 public ham).
Enforces DistilBERT warm=True check, aborting with exit code 1 if not warm.
Evaluates at thresholds 45, 25, 20.
"""

import sys
import os
import csv
import json
import random
from pathlib import Path
import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "aegis-backend"))

from modules.nlp_classifier import warm_up_nlp, is_model_warm, get_model_id
from run_round2_evaluations import evaluate_sample_pipeline, calc_metrics, wilson_ci

def main():
    print("▶ Priming Layer 2 NLP Model (DistilBERT ONNX)...")
    warm_up_nlp()
    if not is_model_warm():
        print("FATAL: DistilBERT model reports warm=False. Evaluation harness aborted.")
        sys.exit(1)

    print(f"DistilBERT Warm: {is_model_warm()} | Model ID: {get_model_id()}")

    naz_csv = REPO_ROOT / "evidence" / "E-39_independent-corpus" / "E-39_nazario_pure_phishing_125.csv"
    test_csv = REPO_ROOT / "evidence" / "E-39_independent-corpus" / "E-39_dataset_test_50.csv"

    if not naz_csv.exists() or not test_csv.exists():
        print("Required CSV files not found.")
        sys.exit(1)

    with open(naz_csv, encoding="utf-8") as f:
        naz_rows = list(csv.DictReader(f))
    with open(test_csv, encoding="utf-8") as f:
        test_rows = list(csv.DictReader(f))

    ham_test = [r for r in test_rows if r["label"] == "0"]

    # Seed 42 80/20 split
    rng = random.Random(42)
    naz_shuffled = list(naz_rows)
    rng.shuffle(naz_shuffled)
    naz_test = naz_shuffled[100:125]

    print(f"Test split: {len(naz_test)} pure Nazario phishing, {len(ham_test)} public ham.")

    combined = naz_test + ham_test
    records = []
    scores = []
    y_true = []

    for r in combined:
        lbl = int(r["label"])
        res = evaluate_sample_pipeline(r, config="full")
        sc = res["score"]
        records.append({
            "id": r["id"],
            "label": lbl,
            "score": sc,
            "pred": res,
        })
        scores.append(sc)
        y_true.append(lbl)

    results = {}
    for t in [45, 25, 20]:
        y_pred = [1 if s >= t else 0 for s in scores]
        m = calc_metrics(y_true, y_pred, scores)
        results[str(t)] = {
            "threshold": t,
            "n_phish_test": len(naz_test),
            "n_ham_test": len(ham_test),
            "tp": m["tp"],
            "fp": m["fp"],
            "tn": m["tn"],
            "fn": m["fn"],
            "recall_pct": m["recall"],
            "recall_ci": m["recall_ci"],
            "fpr_pct": m["fpr"],
            "fpr_ci": m["fpr_ci"],
            "precision_pct": m["precision"],
            "f1_pct": m["f1_score"],
            "accuracy_pct": m["accuracy"],
            "roc_auc": m["roc_auc"],
            "roc_auc_ci": m["roc_auc_ci"],
        }
        print(f"Cut-off {t:2d}: TP={m['tp']:2d}, FP={m['fp']:2d}, TN={m['tn']:2d}, FN={m['fn']:2d} | "
              f"Recall={m['recall']:5.1f}% [{m['recall_ci'][0]:.1f}, {m['recall_ci'][1]:.1f}]% | "
              f"FPR={m['fpr']:4.1f}% [{m['fpr_ci'][0]:.1f}, {m['fpr_ci'][1]:.1f}]% | "
              f"F1={m['f1_score']:5.2f}% | AUC={m['roc_auc']}")

    out_file = REPO_ROOT / "evidence" / "E-39_independent-corpus" / "nazario_only_eval.json"
    payload = {
        "evaluation_note": "Pure Jose Nazario Phishing (125 samples) vs Public Ham (125 samples), seed 42 80/20 holdout test split (N=50). DistilBERT model verified warm.",
        "model_loaded": is_model_warm(),
        "model_id": get_model_id(),
        "split_seed": 42,
        "split_ratio": "80_20",
        "results": results,
    }

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"\nSaved updated results to: {out_file}")

if __name__ == "__main__":
    main()

