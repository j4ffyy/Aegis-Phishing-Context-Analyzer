"""
Evaluate Calibrated Warning Cut-off Unchanged Across All 4 Test Sets
- Set 1: 50-email public test split (E-39)
- Set 2: 60 LLM-authored emails (E-43)
- Set 3: 60 Philippine / Taglish emails (E-42)
- Set 4: 100-sample template benchmark set (E-08 / test_dataset.csv)

Evaluates thresholds:
  - T = 20 (Primary Calibrated Warning Cut-off, Youden-optimal on 200 Train)
  - T = 25 (Conservative Zero-FPR Cut-off on 200 Train)
  - T = 45 (Unchanged Production Baseline)
"""

import sys
import os
import csv
import json
from pathlib import Path
from typing import Dict, Any, List

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

from run_round2_evaluations import calc_metrics, wilson_ci

def load_e39_test(repo_root: Path) -> List[Dict[str, Any]]:
    p = repo_root / "evidence" / "E-39_independent-corpus" / "E-39_predictions_full_standard.csv"
    with open(p, "r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    res = []
    for r in rows:
        res.append({
            "id": r["id"],
            "label": int(r["label"]),
            "score": int(r["score"]),
            "subject": r["subject"],
        })
    return res

def load_e43_llm(repo_root: Path) -> List[Dict[str, Any]]:
    p = repo_root / "evidence" / "E-43_llm-authored-eval" / "E-43_llm_predictions.csv"
    with open(p, "r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    res = []
    for r in rows:
        res.append({
            "id": r["id"],
            "label": int(r["label"]),
            "score": int(r["score"]),
            "subject": r["subject"],
        })
    return res

def load_e42_philippine(repo_root: Path) -> List[Dict[str, Any]]:
    p = repo_root / "evidence" / "E-42_philippine-taglish" / "E-42_philippine_evaluation.csv"
    with open(p, "r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    res = []
    for r in rows:
        res.append({
            "id": r["id"],
            "label": int(r["label"]),
            "score": int(r["full_score"]),
            "subject": r["subject"],
        })
    return res

def load_e08_template(repo_root: Path) -> List[Dict[str, Any]]:
    p = repo_root / "evidence" / "E-08_phishing-corpus-metrics" / "E-08_phishing-corpus-metrics_predictions_20261108_0c541f5.csv"
    with open(p, "r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    res = []
    for r in rows:
        res.append({
            "id": r["id"],
            "label": int(r["label"]),
            "score": int(r["score"]),
            "subject": r["subject"],
        })
    return res

def evaluate_set_at_thresholds(name: str, samples: List[Dict[str, Any]], thresholds: List[int]) -> Dict[str, Any]:
    y_true = [s["label"] for s in samples]
    scores = [s["score"] for s in samples]
    
    out = {
        "dataset_name": name,
        "sample_count": len(samples),
        "phishing_count": sum(1 for y in y_true if y == 1),
        "legitimate_count": sum(1 for y in y_true if y == 0),
        "results_by_threshold": {}
    }
    
    for t in thresholds:
        y_pred = [1 if s >= t else 0 for s in scores]
        m = calc_metrics(y_true, y_pred, scores)
        out["results_by_threshold"][str(t)] = m
        
    return out

def main():
    repo = REPO_ROOT
    datasets = {
        "E-39 Public Test Split (N=50)": load_e39_test(repo),
        "E-43 LLM-Authored Set (N=60)": load_e43_llm(repo),
        "E-42 Philippine/Taglish Set (N=60)": load_e42_philippine(repo),
        "E-08 Template Benchmark Set (N=100)": load_e08_template(repo),
    }

    thresholds = [20, 25, 45]
    all_results = {}

    print("=" * 95)
    print("EVALUATION OF CALIBRATED WARNING CUT-OFF UNCHANGED ACROSS ALL 4 DATASETS")
    print("=" * 95)

    for d_name, d_samples in datasets.items():
        res = evaluate_set_at_thresholds(d_name, d_samples, thresholds)
        all_results[d_name] = res
        print(f"\n>>> Dataset: {d_name} (Total={res['sample_count']}, Phish={res['phishing_count']}, Legit={res['legitimate_count']})")
        print(f"{'Cutoff':>6} | {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3} | {'Accuracy [95% CI]':<26} | {'Recall [95% CI]':<24} | {'FPR [95% CI]':<22} | {'F1':>6}")
        print("-" * 110)
        for t in thresholds:
            m = res["results_by_threshold"][str(t)]
            acc_str = f"{m['accuracy']:.1f}% [{m['accuracy_ci'][0]:.1f}, {m['accuracy_ci'][1]:.1f}]%"
            rec_str = f"{m['recall']:.1f}% [{m['recall_ci'][0]:.1f}, {m['recall_ci'][1]:.1f}]%"
            fpr_str = f"{m['fpr']:.1f}% [{m['fpr_ci'][0]:.1f}, {m['fpr_ci'][1]:.1f}]%"
            print(f"{t:6d} | {m['tp']:3d} {m['fp']:3d} {m['tn']:3d} {m['fn']:3d} | {acc_str:<26} | {rec_str:<24} | {fpr_str:<22} | {m['f1_score']:6.2f}%")

    # Save to JSON
    out_path = repo / "evidence" / "E-39_independent-corpus" / "E-39_calibrated_eval_all_sets.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)

    print(f"\nSaved all results to: {out_path}")

if __name__ == "__main__":
    main()

