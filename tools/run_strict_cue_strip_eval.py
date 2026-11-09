"""
Aegis - Post-Defense Evaluation Tool: Strict Cue-Stripping & Neutral Domain Harness
Specification:
  - Option "strict cue-strip": strips NLP URGENCY_REGEX keywords list (all ~40-50 terms)
  - Variant A: Strict cue-strip with original sender domain
  - Variant B: Strict cue-strip + sender domain replaced with neutral domain (e.g. example.com)
  - Re-evaluates Phase C (Configs 3 and 4), Public Test 50, Taglish 60, and LLM 60 sets
  - Writes E-46-style output with suffix '_rerun3'
"""

import csv
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
from sklearn.metrics import roc_auc_score, f1_score

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "aegis-backend"
TOOLS_DIR = REPO_ROOT / "tools"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from model_guard import ensure_model_loaded_and_warm
from modules.nlp_classifier import classify_email_text, is_model_warm
from modules.meta_classifier import synthesize_composite_score
from routes.analyze import (
    URGENCY_REGEX,
    EmailPayload,
    extract_url_strings,
    evaluate_heuristics,
    evaluate_layer1,
    evaluate_behavioral,
)
import run_round2_evaluations as r2


def apply_strict_strip_and_neutral(
    subject: str,
    body: str,
    sender: str,
    strip_urgency: bool = True,
    neutral_domain: bool = False,
) -> Tuple[str, str, str]:
    """Applies strict URGENCY_REGEX stripping and optional sender domain neutralisation."""
    subj_clean = subject or ""
    body_clean = body or ""
    sender_clean = sender or ""

    if strip_urgency:
        subj_clean = URGENCY_REGEX.sub("", subj_clean).strip()
        body_clean = URGENCY_REGEX.sub("", body_clean).strip()

    if neutral_domain:
        user = sender_clean.split("@")[0] if "@" in sender_clean else "user"
        sender_clean = f"{user}@example.com"

    return subj_clean, body_clean, sender_clean


def evaluate_phase_c_sample(
    row: Dict[str, Any],
    config: str = "full",
    strip_urgency: bool = True,
    neutral_domain: bool = False,
) -> Dict[str, Any]:
    raw_subj = row.get("subject", "") or ""
    raw_body = row.get("bodyText", "") or ""
    raw_sender = row.get("senderEmail", "") or ""

    subject, body, sender = apply_strict_strip_and_neutral(
        raw_subj, raw_body, raw_sender, strip_urgency=strip_urgency, neutral_domain=neutral_domain
    )

    links_raw = row.get("links", "[]")
    try:
        links = json.loads(links_raw) if isinstance(links_raw, str) else links_raw
    except:
        links = []

    attachments_raw = row.get("attachments", "[]")
    try:
        attachments = json.loads(attachments_raw) if isinstance(attachments_raw, str) else attachments_raw
    except:
        attachments = []

    payload = EmailPayload(
        senderEmail=sender,
        subject=subject,
        bodyText=body,
        links=links,
        attachments=attachments,
        hasAttachment=bool(attachments),
        attachmentCount=len(attachments),
        spfPass=True,
        dkimPass=True,
    )

    urls = extract_url_strings(payload.links or [])

    if config == "heuristics_nlp_no_ensemble":
        heur = evaluate_heuristics(payload)
        s_h = heur["score"]
        kw_hits = heur["keyword_hits"]
        has_typo = heur.get("has_typosquatting", False)
        text = f"{subject}\n\n{body}".strip()
        urgency_penalty = min(kw_hits * 8, 20)
        bec_penalty = 20 if has_typo else 0
        nlp_res = classify_email_text(text=text, urgency_penalty=urgency_penalty, bec_penalty=bec_penalty)
        s_nlp = nlp_res["nlp_score"]
        s_b = evaluate_behavioral(payload)
        final_score = synthesize_composite_score(
            s_heuristic=s_h, s_nlp=s_nlp, s_behavioral=s_b, s_vt=0, vt_pending=True
        )
        flags = heur.get("flags", [])
        has_att = any("Attachment" in f.get("title", "") for f in flags)
        has_urg = any("Urgency" in f.get("title", "") for f in flags) or s_nlp >= 25
        if (has_att and has_urg) or s_h >= 40:
            if final_score < 52:
                final_score = 52
    else:  # full
        layer1 = evaluate_layer1(payload, urls)
        s_h = layer1["score"]
        kw_hits = layer1["keyword_hits"]
        has_typo = layer1.get("has_typosquatting", False)
        text = f"{subject}\n\n{body}".strip()
        urgency_penalty = min(kw_hits * 8, 20)
        bec_penalty = 20 if has_typo else 0
        nlp_res = classify_email_text(text=text, urgency_penalty=urgency_penalty, bec_penalty=bec_penalty)
        s_nlp = nlp_res["nlp_score"]
        s_b = evaluate_behavioral(payload)
        final_score = synthesize_composite_score(
            s_heuristic=s_h, s_nlp=s_nlp, s_behavioral=s_b, s_vt=0, vt_pending=True
        )
        flags = layer1.get("flags", [])
        has_att = any("Attachment" in f.get("title", "") for f in flags)
        has_urg = any("Urgency" in f.get("title", "") for f in flags) or s_nlp >= 25
        if (has_att and has_urg) or s_h >= 40:
            if final_score < 52:
                final_score = 52

    return {
        "id": row.get("id"),
        "label": int(row.get("label") or 0),
        "score": final_score,
        "pred": 1 if final_score >= 45 else 0,
        "s_nlp": s_nlp,
    }


def evaluate_round2_sample(
    sample: Dict[str, Any],
    config: str = "full",
    strip_urgency: bool = True,
    neutral_domain: bool = False,
) -> Dict[str, Any]:
    raw_subj = sample.get("subject", "") or ""
    raw_body = sample.get("bodyText", "") or ""
    raw_sender = sample.get("senderEmail", "") or ""

    subject, body, sender = apply_strict_strip_and_neutral(
        raw_subj, raw_body, raw_sender, strip_urgency=strip_urgency, neutral_domain=neutral_domain
    )

    payload_dict = {
        "senderEmail": sender,
        "subject": subject,
        "bodyText": body,
        "links": sample.get("links", "[]"),
        "attachments": sample.get("attachments", "[]"),
    }

    res = r2.evaluate_sample_pipeline(payload_dict, config=config)
    lbl = int(sample.get("label", 0))

    return {
        "id": sample.get("id"),
        "label": lbl,
        "score": res["score"],
        "pred": res["pred_label"],
        "s_heuristic": res.get("s_heuristic", 0),
        "s_nlp": res.get("s_nlp", 0),
    }


def compute_metrics(labels: List[int], scores: List[float]) -> Dict[str, Any]:
    preds = [1 if s >= 45 else 0 for s in scores]
    tp = sum(1 for yt, yp in zip(labels, preds) if yt == 1 and yp == 1)
    tn = sum(1 for yt, yp in zip(labels, preds) if yt == 0 and yp == 0)
    fp = sum(1 for yt, yp in zip(labels, preds) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(labels, preds) if yt == 1 and yp == 0)

    rec = (tp / (tp + fn) * 100.0) if (tp + fn) > 0 else 0.0
    fpr = (fp / (fp + tn) * 100.0) if (fp + tn) > 0 else 0.0
    acc = ((tp + tn) / len(labels) * 100.0) if labels else 0.0
    f1 = (f1_score(labels, preds) * 100.0) if len(set(labels)) > 1 else 0.0
    try:
        auc = roc_auc_score(labels, scores) if len(set(labels)) > 1 else 0.5
    except:
        auc = 0.5

    return {
        "n": len(labels),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "recall": round(rec, 2),
        "fpr": round(fpr, 2),
        "accuracy": round(acc, 2),
        "f1": round(f1, 2),
        "auc": round(auc, 4),
    }


def run_all_strict_evaluations():
    print("=" * 80)
    print("  AEGIS STRICT CUE-STRIP & NEUTRAL DOMAIN BENCHMARK SUITE (_rerun3)")
    print("=" * 80)

    ensure_model_loaded_and_warm()

    out_dir = REPO_ROOT / "evidence" / "E-46_nlp-base-only"
    out_dir.mkdir(parents=True, exist_ok=True)

    master_summary = []

    # -------------------------------------------------------------------------
    # 1. Phase C Ablation (Configs 3 and 4) under Strict Strip + Neutral Domain
    # -------------------------------------------------------------------------
    print("\n[1/4] Running Phase C Ablation (Configs 3 & 4)...")
    phase_c_file = REPO_ROOT / "aegis-backend" / "data" / "test_dataset.csv"
    with open(phase_c_file, "r", encoding="utf-8") as f:
        phase_c_rows = list(csv.DictReader(f))

    labels_phase_c = [int(r["label"]) for r in phase_c_rows]

    for cfg_code, cfg_name in [
        ("heuristics_nlp_no_ensemble", "Phase C Config 3 (Heuristics + DistilBERT)"),
        ("full", "Phase C Config 4 (Full Pipeline)"),
    ]:
        for nd in [False, True]:
            cond = "Strict Cue-Strip (Neutral Domain)" if nd else "Strict Cue-Strip (Original Domain)"
            res_list = [
                evaluate_phase_c_sample(r, config=cfg_code, strip_urgency=True, neutral_domain=nd)
                for r in phase_c_rows
            ]
            scores = [x["score"] for x in res_list]
            m = compute_metrics(labels_phase_c, scores)

            master_summary.append({
                "dataset": cfg_name,
                "variant": cond,
                "n_samples": m["n"],
                "recall": f"{m['recall']:.2f}%",
                "fpr": f"{m['fpr']:.2f}%",
                "f1": f"{m['f1']:.2f}%",
                "auc": f"{m['auc']:.4f}",
            })
            print(f"  {cfg_name} | {cond}: Recall={m['recall']}% | FPR={m['fpr']}% | AUC={m['auc']}")

    # -------------------------------------------------------------------------
    # 2. Public Test Split (50 samples, E-39)
    # -------------------------------------------------------------------------
    print("\n[2/4] Running Public Test Split (50 samples)...")
    pub_file = REPO_ROOT / "evidence" / "E-39_independent-corpus" / "E-39_dataset_test_50_rerun2.csv"
    if not pub_file.exists():
        pub_file = REPO_ROOT / "evidence" / "E-39_independent-corpus" / "E-39_dataset_test_50.csv"
    with open(pub_file, "r", encoding="utf-8") as f:
        pub_rows = list(csv.DictReader(f))

    labels_pub = [int(r["label"]) for r in pub_rows]

    for cfg_code, cfg_name in [
        ("heuristics_distilbert", "Public Test Config 3 (Heuristics + DistilBERT)"),
        ("full", "Public Test Config 4 (Full Pipeline)"),
    ]:
        for nd in [False, True]:
            cond = "Strict Cue-Strip (Neutral Domain)" if nd else "Strict Cue-Strip (Original Domain)"
            scores = []
            for r in pub_rows:
                res = evaluate_round2_sample(r, config=cfg_code, strip_urgency=True, neutral_domain=nd)
                scores.append(res["score"])
            m = compute_metrics(labels_pub, scores)
            master_summary.append({
                "dataset": cfg_name,
                "variant": cond,
                "n_samples": m["n"],
                "recall": f"{m['recall']:.2f}%",
                "fpr": f"{m['fpr']:.2f}%",
                "f1": f"{m['f1']:.2f}%",
                "auc": f"{m['auc']:.4f}",
            })
            print(f"  {cfg_name} | {cond}: Recall={m['recall']}% | FPR={m['fpr']}% | AUC={m['auc']}")

    # -------------------------------------------------------------------------
    # 3. Philippine / Taglish Benchmark (60 samples, E-42)
    # -------------------------------------------------------------------------
    print("\n[3/4] Running Philippine / Taglish Corpus (60 samples)...")
    # Capture raw samples via temporary hook
    temp_dir = REPO_ROOT / "temp_hook"
    temp_dir.mkdir(parents=True, exist_ok=True)
    captured_ph = []
    orig_eval = r2.evaluate_sample_pipeline

    def cap_ph(p, config="full", strip_urgency=False):
        captured_ph.append(dict(p))
        return orig_eval(p, config=config, strip_urgency=strip_urgency)

    r2.evaluate_sample_pipeline = cap_ph
    r2.run_item4_eval(temp_dir, "rerun3")
    r2.evaluate_sample_pipeline = orig_eval

    # Deduplicate captured samples
    seen = set()
    ph_samples = []
    for s in captured_ph:
        key = (s["senderEmail"], s["subject"])
        if key not in seen:
            seen.add(key)
            ph_samples.append(s)

    # Load ground truth labels from E-42 CSV
    e42_ref = REPO_ROOT / "evidence" / "E-42_philippine-taglish" / "E-42_philippine_evaluation_rerun2.csv"
    with open(e42_ref, "r", encoding="utf-8") as f:
        labels_ph = [int(r["label"]) for r in csv.DictReader(f)]

    for nd in [False, True]:
        cond = "Strict Cue-Strip (Neutral Domain)" if nd else "Strict Cue-Strip (Original Domain)"
        scores = []
        for s in ph_samples:
            res = evaluate_round2_sample(s, config="full", strip_urgency=True, neutral_domain=nd)
            scores.append(res["score"])
        m = compute_metrics(labels_ph, scores)
        master_summary.append({
            "dataset": "Philippine / Taglish Set (Full Pipeline)",
            "variant": cond,
            "n_samples": m["n"],
            "recall": f"{m['recall']:.2f}%",
            "fpr": f"{m['fpr']:.2f}%",
            "f1": f"{m['f1']:.2f}%",
            "auc": f"{m['auc']:.4f}",
        })
        print(f"  Taglish 60 | {cond}: Recall={m['recall']}% | FPR={m['fpr']}% | AUC={m['auc']}")

    # -------------------------------------------------------------------------
    # 4. LLM-Authored Benchmark (60 samples, E-43)
    # -------------------------------------------------------------------------
    print("\n[4/4] Running LLM-Authored Corpus (60 samples)...")
    captured_llm = []

    def cap_llm(p, config="full", strip_urgency=False):
        captured_llm.append(dict(p))
        return orig_eval(p, config=config, strip_urgency=strip_urgency)

    r2.evaluate_sample_pipeline = cap_llm
    r2.run_item5_eval(temp_dir, "rerun3")
    r2.evaluate_sample_pipeline = orig_eval

    seen_llm = set()
    llm_samples = []
    for s in captured_llm:
        key = (s["senderEmail"], s["subject"])
        if key not in seen_llm:
            seen_llm.add(key)
            llm_samples.append(s)

    e43_ref = REPO_ROOT / "evidence" / "E-43_llm-authored-eval" / "E-43_llm_predictions_rerun2.csv"
    with open(e43_ref, "r", encoding="utf-8") as f:
        labels_llm = [int(r["label"]) for r in csv.DictReader(f)]

    for nd in [False, True]:
        cond = "Strict Cue-Strip (Neutral Domain)" if nd else "Strict Cue-Strip (Original Domain)"
        scores = []
        for s in llm_samples:
            res = evaluate_round2_sample(s, config="full", strip_urgency=True, neutral_domain=nd)
            scores.append(res["score"])
        m = compute_metrics(labels_llm, scores)
        master_summary.append({
            "dataset": "LLM-Authored Set (Full Pipeline)",
            "variant": cond,
            "n_samples": m["n"],
            "recall": f"{m['recall']:.2f}%",
            "fpr": f"{m['fpr']:.2f}%",
            "f1": f"{m['f1']:.2f}%",
            "auc": f"{m['auc']:.4f}",
        })
        print(f"  LLM 60 | {cond}: Recall={m['recall']}% | FPR={m['fpr']}% | AUC={m['auc']}")

    # Clean up temp_hook
    import shutil
    shutil.rmtree(temp_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # Save Master Summary CSV
    # -------------------------------------------------------------------------
    out_csv = out_dir / "E-46_strict_cue_strip_rerun3.csv"
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["dataset", "variant", "n_samples", "recall", "fpr", "f1", "auc"])
        writer.writeheader()
        writer.writerows(master_summary)

    print(f"\n[Done] Summary saved to: {out_csv}")
    return master_summary


if __name__ == "__main__":
    run_all_strict_evaluations()
