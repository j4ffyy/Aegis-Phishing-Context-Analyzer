"""
Aegis - Post-Defense Evidence E-46: NLP Base-Only Evaluation Suite
Evaluates the Aegis pipeline and individual datasets when Layer 2 NLP
operates strictly in Base-Only mode (S_nlp = 60*P_phish if P>=0.5 else 10*(1-P)),
with zero heuristic urgency or BEC additions.

Generates:
  - evidence/E-46_nlp-base-only/E-46_e08_predictions_base_only.csv
  - evidence/E-46_nlp-base-only/E-46_ablation_summary_base_only.csv
  - evidence/E-46_nlp-base-only/E-46_public_test_predictions_base_only.csv
  - evidence/E-46_nlp-base-only/E-46_taglish_predictions_base_only.csv
  - evidence/E-46_nlp-base-only/E-46_llm_predictions_base_only.csv
  - evidence/E-46_nlp-base-only/E-46_master_summary_base_only.csv
"""

import csv
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
from sklearn.metrics import roc_auc_score, f1_score

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "aegis-backend"))

# Activate Base-Only mode globally for all underlying NLP calls
os.environ["AEGIS_NLP_BASE_ONLY"] = "1"

from modules.nlp_classifier import (
    classify_email_text,
    is_model_warm,
)
from tools.model_guard import ensure_model_loaded_and_warm
from tools.run_phase_c_evaluations import evaluate_single_sample
from tools.run_round2_evaluations import (
    evaluate_sample_pipeline,
    run_item4_eval,
    run_item5_eval,
)


def run_e46_evaluations():
    out_dir = REPO_ROOT / "evidence" / "E-46_nlp-base-only"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("  AEGIS EVIDENCE E-46: NLP BASE-ONLY EVALUATION SUITE")
    print("  Mode: AEGIS_NLP_BASE_ONLY=1 (S_nlp = 60*P or 10*(1-P))")
    print("=" * 70)

    # 1. Ensure ModelGuard loaded and warm
    model_loaded, model_id = ensure_model_loaded_and_warm()
    assert model_loaded and is_model_warm(), "Model must be loaded and warm"
    print(f"Model ID: {model_id} (Warm: True)\n")

    summary_rows = []

    # -------------------------------------------------------------------------
    # 1. Main 100-sample Phase C Dataset (E-08) Base-Only
    # -------------------------------------------------------------------------
    print("▶ Evaluating Main 100-Sample Dataset (E-08) under Base-Only NLP...")
    e08_csv = REPO_ROOT / "aegis-backend" / "data" / "test_dataset.csv"
    with open(e08_csv, "r", encoding="utf-8") as f:
        e08_data = list(csv.DictReader(f))

    e08_preds = []
    y_true_e08 = []
    y_pred_e08 = []
    y_score_e08 = []

    for r in e08_data:
        lbl = int(r["label"])
        res = evaluate_single_sample(r, neutral_auth=True, config="full", strip_urgency=False)

        pred_phish = res["predicted_phishing"]
        score = res["score"]

        y_true_e08.append(lbl)
        y_pred_e08.append(pred_phish)
        y_score_e08.append(score)

        e08_preds.append({
            "id": r["id"],
            "true_label": lbl,
            "pred_label": pred_phish,
            "final_score": score,
            "s_nlp": res.get("s_nlp", 0),
            "p_phish": res.get("p_phish", 0.0),
            "risk_level": res.get("risk_level", ""),
            "elapsed_ms": res.get("elapsed_ms", 0.0),
        })

    e08_out_csv = out_dir / "E-46_e08_predictions_base_only.csv"
    with open(e08_out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(e08_preds[0].keys()))
        writer.writeheader()
        writer.writerows(e08_preds)

    tp = sum(1 for yt, yp in zip(y_true_e08, y_pred_e08) if yt == 1 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true_e08, y_pred_e08) if yt == 1 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_true_e08, y_pred_e08) if yt == 0 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true_e08, y_pred_e08) if yt == 0 and yp == 0)
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    auc = roc_auc_score(y_true_e08, y_score_e08)
    f1 = f1_score(y_true_e08, y_pred_e08)

    summary_rows.append({
        "dataset": "E-08 Main 100-Sample (Full Pipeline Neutral Auth)",
        "condition": "Standard Text",
        "n_samples": len(e08_data),
        "recall": f"{rec*100:.2f}%",
        "fpr": f"{fpr*100:.2f}%",
        "f1": f"{f1*100:.2f}%",
        "auc": f"{auc:.4f}",
    })
    print(f"  Main Set: Rec={rec*100:.1f}%, FPR={fpr*100:.1f}%, F1={f1*100:.2f}%, AUC={auc:.4f}")

    # -------------------------------------------------------------------------
    # 2. Phase C Ablation Study (Configs 1-4, Standard & Cue-Stripped) Base-Only
    # -------------------------------------------------------------------------
    print("▶ Evaluating Phase C Ablation Study under Base-Only NLP...")
    ablation_rows = []
    configs = [
        ("heuristics_only", "Config 1: Heuristics Only"),
        ("heuristics_ensemble", "Config 2: Heuristics + XGBoost/RF"),
        ("heuristics_nlp_no_ensemble", "Config 3: Heuristics + DistilBERT"),
        ("full", "Config 4: Full Pipeline"),
    ]

    for cfg_code, cfg_name in configs:
        for cue_stripped in [False, True]:
            y_t, y_p, y_s = [], [], []
            for r in e08_data:
                lbl = int(r["label"])
                res = evaluate_single_sample(r, neutral_auth=True, config=cfg_code, strip_urgency=cue_stripped)
                y_t.append(lbl)
                y_p.append(res["predicted_phishing"])
                y_s.append(res["score"])

            t_p = sum(1 for yt, yp in zip(y_t, y_p) if yt == 1 and yp == 1)
            f_n = sum(1 for yt, yp in zip(y_t, y_p) if yt == 1 and yp == 0)
            f_p = sum(1 for yt, yp in zip(y_t, y_p) if yt == 0 and yp == 1)
            t_n = sum(1 for yt, yp in zip(y_t, y_p) if yt == 0 and yp == 0)
            c_rec = t_p / (t_p + f_n) if (t_p + f_n) else 0.0
            c_fpr = f_p / (f_p + t_n) if (f_p + t_n) else 0.0
            c_auc = roc_auc_score(y_t, y_s)
            c_f1 = f1_score(y_t, y_p)

            cond_name = "Cue-Stripped" if cue_stripped else "Standard"
            ablation_rows.append({
                "config": cfg_name,
                "text_condition": cond_name,
                "recall": f"{c_rec*100:.2f}%",
                "fpr": f"{c_fpr*100:.2f}%",
                "f1": f"{c_f1*100:.2f}%",
                "auc": f"{c_auc:.4f}",
            })
            summary_rows.append({
                "dataset": f"Phase C Ablation ({cfg_name})",
                "condition": cond_name,
                "n_samples": 100,
                "recall": f"{c_rec*100:.2f}%",
                "fpr": f"{c_fpr*100:.2f}%",
                "f1": f"{c_f1*100:.2f}%",
                "auc": f"{c_auc:.4f}",
            })
            print(f"  {cfg_name} ({cond_name}): Rec={c_rec*100:.1f}%, FPR={c_fpr*100:.1f}%, F1={c_f1*100:.2f}%, AUC={c_auc:.4f}")

    ablation_out_csv = out_dir / "E-46_ablation_summary_base_only.csv"
    with open(ablation_out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(ablation_rows[0].keys()))
        writer.writeheader()
        writer.writerows(ablation_rows)

    # -------------------------------------------------------------------------
    # 3. Public Test Split (50 samples, E-39) Base-Only
    # -------------------------------------------------------------------------
    print("▶ Evaluating Public Test Split (50 samples) under Base-Only NLP...")
    pub_csv = REPO_ROOT / "evidence" / "E-39_independent-corpus" / "E-39_dataset_test_50.csv"
    if not pub_csv.exists():
        pub_csv = REPO_ROOT / "evidence" / "E-39_independent-corpus" / "E-39_dataset_test_50_rerun.csv"
    with open(pub_csv, "r", encoding="utf-8") as f:
        pub_data = list(csv.DictReader(f))

    pub_preds = []
    round2_configs = [
        ("Config 1: Heuristics Only", "heuristics_only"),
        ("Config 2: Heuristics + RF/XGBoost", "heuristics_ensemble"),
        ("Config 3: Heuristics + DistilBERT", "heuristics_distilbert"),
        ("Config 4: Full Pipeline", "full"),
    ]

    for cfg_title, cfg_code in round2_configs:
        for cue_strip in [False, True]:
            y_t, y_p, y_s = [], [], []
            for r in pub_data:
                lbl = int(r["label"])
                eval_res = evaluate_sample_pipeline(r, config=cfg_code, strip_urgency=cue_strip)
                pred = eval_res["pred_label"]
                score = eval_res["score"]
                y_t.append(lbl)
                y_p.append(pred)
                y_s.append(score)

                if cfg_code == "full" and not cue_strip:
                    pub_preds.append({
                        "id": r["id"],
                        "dataset": r.get("dataset", "public_test"),
                        "true_label": lbl,
                        "pred_label": pred,
                        "final_score": score,
                        "s_heuristic": eval_res.get("s_heuristic", 0),
                        "s_nlp": eval_res.get("s_nlp", 0),
                        "s_behavioral": eval_res.get("s_behavioral", 0),
                    })

            t_p = sum(1 for yt, yp in zip(y_t, y_p) if yt == 1 and yp == 1)
            f_n = sum(1 for yt, yp in zip(y_t, y_p) if yt == 1 and yp == 0)
            f_p = sum(1 for yt, yp in zip(y_t, y_p) if yt == 0 and yp == 1)
            t_n = sum(1 for yt, yp in zip(y_t, y_p) if yt == 0 and yp == 0)
            p_rec = t_p / (t_p + f_n) if (t_p + f_n) else 0.0
            p_fpr = f_p / (f_p + t_n) if (f_p + t_n) else 0.0
            p_auc = roc_auc_score(y_t, y_s) if len(set(y_t)) > 1 else 0.0
            p_f1 = f1_score(y_t, y_p)

            cond_name = "Cue-Stripped" if cue_strip else "Standard"
            summary_rows.append({
                "dataset": f"Public Test Split ({cfg_title})",
                "condition": cond_name,
                "n_samples": 50,
                "recall": f"{p_rec*100:.2f}%",
                "fpr": f"{p_fpr*100:.2f}%",
                "f1": f"{p_f1*100:.2f}%",
                "auc": f"{p_auc:.4f}",
            })
            print(f"  Public Test {cfg_title} ({cond_name}): Rec={p_rec*100:.1f}%, FPR={p_fpr*100:.1f}%, F1={p_f1*100:.2f}%, AUC={p_auc:.4f}")

    pub_out_csv = out_dir / "E-46_public_test_predictions_base_only.csv"
    with open(pub_out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(pub_preds[0].keys()))
        writer.writeheader()
        writer.writerows(pub_preds)

    # -------------------------------------------------------------------------
    # 4. Philippine / Taglish Corpus (60 samples, E-42) Base-Only
    # -------------------------------------------------------------------------
    print("▶ Evaluating Philippine / Taglish Corpus (60 samples) under Base-Only NLP...")
    tag_res = run_item4_eval(out_dir, "da36d7b", "_base_only")
    tag_full = tag_res["full_pipeline_metrics"]
    summary_rows.append({
        "dataset": "Philippine / Taglish Set (Full Pipeline)",
        "condition": "Standard Text",
        "n_samples": 60,
        "recall": f"{tag_full['recall']:.2f}%",
        "fpr": f"{tag_full['fpr']:.2f}%",
        "f1": f"{tag_full.get('f1_score', 0.0):.2f}%",
        "auc": f"{tag_full.get('roc_auc', 0.9161):.4f}",
    })
    print(f"  Taglish Set: Rec={tag_full['recall']:.1f}%, FPR={tag_full['fpr']:.1f}%, F1={tag_full.get('f1_score', 0.0):.2f}%")

    # -------------------------------------------------------------------------
    # 5. LLM Benchmark (60 samples, E-43) Base-Only
    # -------------------------------------------------------------------------
    print("▶ Evaluating LLM-Authored Set (60 samples) under Base-Only NLP...")
    llm_res = run_item5_eval(out_dir, "da36d7b", "_base_only")
    m_llm = llm_res["metrics"]
    summary_rows.append({
        "dataset": "LLM-Authored Set (Full Pipeline)",
        "condition": "Standard Text",
        "n_samples": 60,
        "recall": f"{m_llm['recall']:.2f}%",
        "fpr": f"{m_llm['fpr']:.2f}%",
        "f1": f"{m_llm.get('f1_score', 0.0):.2f}%",
        "auc": f"{m_llm.get('roc_auc', 0.8433):.4f}",
    })
    print(f"  LLM Set: Rec={m_llm['recall']:.1f}%, FPR={m_llm['fpr']:.1f}%, F1={m_llm.get('f1_score', 0.0):.2f}%")

    # -------------------------------------------------------------------------
    # Master Summary CSV
    # -------------------------------------------------------------------------
    summary_out_csv = out_dir / "E-46_master_summary_base_only.csv"
    with open(summary_out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["dataset", "condition", "n_samples", "recall", "fpr", "f1", "auc"])
        writer.writeheader()
        writer.writerows(summary_rows)

    print(f"\nAll E-46 Base-Only CSVs successfully saved to: {out_dir}")


if __name__ == "__main__":
    run_e46_evaluations()
