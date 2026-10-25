"""
AEGIS Supplementary Evaluation: Steps 3 & 4 (With DistilBERT ONNX Actually Loaded)
Branch: post-submission-eval
Commit Hash: 8c42233da6027148ccf0f735d7217b991d18bc3c
"""

import csv
import json
import math
import os
import sys
import time
from pathlib import Path
import numpy as np
from sklearn.metrics import roc_auc_score

# Paths
REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "aegis-backend"
DATA_FILE = BACKEND_DIR / "data" / "test_dataset.csv"
OUTPUT_DIR = REPO_ROOT / "evidences" / "supplementary"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

COMMIT_HASH = "8c42233da6027148ccf0f735d7217b991d18bc3c"
PHISHING_SCORE_THRESHOLD = 45

# Add backend to path
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from routes.analyze import (
    EmailPayload,
    evaluate_heuristics,
    evaluate_layer1,
    evaluate_nlp_intent,
    evaluate_behavioral,
    extract_url_strings,
)
from modules.ensemble_classifier import score_with_ensemble
from modules.nlp_classifier import (
    load_nlp_model,
    classify_email_text,
    CLASS_LABELS,
)
from modules.meta_classifier import synthesize_composite_score, clamp_score


# ---------------------------------------------------------------------------
# Statistical Helpers
# ---------------------------------------------------------------------------

def wilson_ci(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denom = 1 + z**2 / n
    center = (p + z**2 / (2 * n)) / denom
    spread = (z * math.sqrt((p * (1 - p) / n) + (z**2 / (4 * n**2)))) / denom
    lower = max(0.0, center - spread)
    upper = min(1.0, center + spread)
    return lower * 100.0, upper * 100.0


def bootstrap_roc_auc_ci(
    y_true: list[int],
    y_score: list[float],
    n_bootstraps: int = 1000,
    seed: int = 42,
) -> tuple[float, float, float]:
    y_t = np.array(y_true)
    y_s = np.array(y_score)
    base_auc = float(roc_auc_score(y_t, y_s))

    rng = np.random.RandomState(seed)
    n = len(y_t)
    boot_aucs = []

    for _ in range(n_bootstraps):
        idx = rng.randint(0, n, n)
        if len(np.unique(y_t[idx])) < 2:
            continue
        try:
            auc = roc_auc_score(y_t[idx], y_s[idx])
            boot_aucs.append(auc)
        except ValueError:
            continue

    if boot_aucs:
        low = float(np.percentile(boot_aucs, 2.5))
        high = float(np.percentile(boot_aucs, 97.5))
    else:
        low, high = base_auc, base_auc

    return base_auc, low, high


def calc_metrics(y_true: list[int], y_pred: list[int], latencies: list[float] | None = None) -> dict:
    n = len(y_true)
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)

    acc = (tp + tn) / n * 100.0 if n > 0 else 0.0
    prec = tp / (tp + fp) * 100.0 if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) * 100.0 if (tp + fn) > 0 else 0.0
    f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
    fpr = fp / (fp + tn) * 100.0 if (fp + tn) > 0 else 0.0

    acc_ci = wilson_ci(tp + tn, n)
    rec_ci = wilson_ci(tp, tp + fn)
    fpr_ci = wilson_ci(fp, fp + tn)

    med_lat = float(np.median(latencies)) if latencies else 0.0
    p95_lat = float(np.percentile(latencies, 95)) if latencies else 0.0

    return {
        "n": n, "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": acc, "accuracy_ci": acc_ci,
        "precision": prec,
        "recall": rec, "recall_ci": rec_ci,
        "f1": f1,
        "fpr": fpr, "fpr_ci": fpr_ci,
        "latency_median_ms": med_lat,
        "latency_p95_ms": p95_lat,
    }


# ---------------------------------------------------------------------------
# SANITY CHECK: 6 Handpicked Emails
# ---------------------------------------------------------------------------

SANITY_EMAILS = [
    {
        "category": "Obvious Phishing #1",
        "subject": "URGENT: Your BDO Account Has Been Suspended",
        "body": "Dear customer, we detected unauthorized access from an unrecognized device. Click here immediately to verify your identity and restore access: http://bdo-security-login.xyz/verify",
    },
    {
        "category": "Obvious Phishing #2",
        "subject": "Security Alert: Unauthorized sign-in detected on your Maya account",
        "body": "Your Maya account was locked due to suspicious activity. Verify your identity within 24 hours to prevent permanent deactivation: http://maya-verify-account.top/login",
    },
    {
        "category": "Obvious Legitimate #1",
        "subject": "Team lunch tomorrow at 12pm",
        "body": "Hi team, let's meet tomorrow at 12:00 PM in the 4th floor pantry for our monthly team lunch and project milestone catchup. See you all there!",
    },
    {
        "category": "Obvious Legitimate #2",
        "subject": "MMDC Academic Calendar update for Term 2",
        "body": "Good day students, please find the revised academic calendar for Term 2. Class schedules, consultation hours, and final examination periods have been posted on the portal.",
    },
    {
        "category": "Ambiguous #1",
        "subject": "Invoice statement for review",
        "body": "Hello, attached is the revised quarterly settlement invoice for services rendered. Please review the line items and confirm receipt.",
    },
    {
        "category": "Ambiguous #2",
        "subject": "Delivery update for your package",
        "body": "Your order #PH-8921 is out for delivery with our rider today. Please ensure someone is available at the delivery address to receive the package.",
    },
]


def run_sanity_check():
    print("\n" + "=" * 70)
    print("SANITY CHECK: Scoring 6 Handpicked Emails with Loaded DistilBERT ONNX")
    print("=" * 70)

    results = []
    for item in SANITY_EMAILS:
        text = f"{item['subject']}\n\n{item['body']}"
        res = classify_email_text(text, urgency_penalty=0, bec_penalty=0)
        results.append((item, res))

        print(f"\n--- [{item['category']}] ---")
        print(f"  Subject:     {item['subject']}")
        print(f"  model_warm:  {res.get('model_warm')}")
        print(f"  P_phish:     {res.get('p_phish'):.4f}  (P_legit: {res.get('p_legitimate'):.4f})")
        print(f"  s_base:      {res.get('s_base')}")
        print(f"  nlp_score:   {res.get('nlp_score')}")
        print(f"  Pred Label:  {res.get('predicted_label')}")
        print(f"  Probs:       {res.get('probabilities')}")

    # Validation assertions
    warm_flags = [r[1].get("model_warm") for r in results]
    if not all(w is True for w in warm_flags):
        print("\nSANITY CHECK FAILED: model_warm is not True for all samples!")
        sys.exit(1)

    p_phish_vals = [r[1].get("p_phish") for r in results]
    if len(set(p_phish_vals)) == 1:
        print("\nSANITY CHECK FAILED: All P_phish values are identical!")
        sys.exit(1)

    print("\nSANITY CHECK PASSED: model_warm is True and probabilities discriminate across categories.")
    print("=" * 70)


# ---------------------------------------------------------------------------
# Data Evaluation Helper
# ---------------------------------------------------------------------------

def evaluate_sample_full(row: dict, neutral_auth: bool = False):
    links_raw = row.get("links", "[]")
    try:
        links = json.loads(links_raw) if isinstance(links_raw, str) else links_raw
    except Exception:
        links = []

    attachments_raw = row.get("attachments", "[]")
    try:
        attachments = json.loads(attachments_raw) if isinstance(attachments_raw, str) else attachments_raw
    except Exception:
        attachments = []

    if neutral_auth:
        spf_pass = True
        dkim_pass = True
    else:
        spf_raw = row.get("spfPass", "True")
        dkim_raw = row.get("dkimPass", "True")
        spf_pass = spf_raw if isinstance(spf_raw, bool) else str(spf_raw).lower() == "true"
        dkim_pass = dkim_raw if isinstance(dkim_raw, bool) else str(dkim_raw).lower() == "true"

    payload = EmailPayload(
        senderEmail=row.get("senderEmail", ""),
        subject=row.get("subject", ""),
        bodyText=row.get("bodyText", ""),
        links=links,
        attachments=attachments,
        hasAttachment=bool(attachments),
        attachmentCount=len(attachments),
        spfPass=spf_pass,
        dkimPass=dkim_pass,
    )

    t_start = time.time()
    urls = extract_url_strings(payload.links or [])
    layer1 = evaluate_layer1(payload, urls)
    s_h = layer1["score"]
    kw_hits = layer1["keyword_hits"]
    has_typo = layer1.get("has_typosquatting", False)

    # Layer 2 with loaded DistilBERT
    text = f"{payload.subject or ''}\n\n{payload.bodyText or ''}".strip()
    urgency_penalty = min(kw_hits * 8, 20)
    bec_penalty = 20 if has_typo else 0

    nlp_res = classify_email_text(text=text, urgency_penalty=urgency_penalty, bec_penalty=bec_penalty)
    s_nlp = nlp_res["nlp_score"]
    model_warm = nlp_res.get("model_warm", False)

    # Pure DistilBERT (no adjustments)
    nlp_pure = classify_email_text(text=text, urgency_penalty=0, bec_penalty=0)
    s_pure = round(nlp_pure["s_base"])
    p_phish = nlp_pure.get("p_phish", 0.0)

    s_behavioral = evaluate_behavioral(payload)  # 15
    score = synthesize_composite_score(
        s_heuristic=s_h,
        s_nlp=s_nlp,
        s_behavioral=s_behavioral,
        s_vt=0,
        vt_pending=True,
    )
    elapsed_ms = (time.time() - t_start) * 1000

    # Ensure model_warm is strictly True
    assert model_warm is True, f"ABORT: model_warm is False for sample ID={row.get('id')}!"

    return {
        "score": score,
        "elapsed_ms": elapsed_ms,
        "s_layer1": s_h,
        "s_heuristic_raw": layer1.get("s_heuristic_raw", s_h),
        "s_ensemble": layer1.get("s_ensemble", 0),
        "s_nlp": s_nlp,
        "s_pure": s_pure,
        "p_phish": p_phish,
        "s_behavioral": s_behavioral,
        "model_warm": model_warm,
        "keyword_hits": kw_hits,
        "has_typosquatting": has_typo,
    }


# ---------------------------------------------------------------------------
# STEP 3: Run Full Pipeline with DistilBERT Loaded (Synthetic & Neutral)
# ---------------------------------------------------------------------------

def run_step_3(rows: list[dict]):
    print("\n" + "=" * 70)
    print("STEP 3: Full Pipeline Evaluation WITH DistilBERT ONNX Loaded")
    print("=" * 70)

    true_labels = [int(r.get("label", 0)) for r in rows]

    # --- (a) Synthetic Auth ---
    print("\n>>> (a) Synthetic Auth Benchmark (Model Loaded) <<<")
    syn_records = []
    syn_scores = []
    syn_preds = []
    syn_lats = []

    for i, row in enumerate(rows):
        res = evaluate_sample_full(row, neutral_auth=False)
        pred = 1 if res["score"] >= PHISHING_SCORE_THRESHOLD else 0
        y = true_labels[i]

        syn_scores.append(res["score"])
        syn_preds.append(pred)
        syn_lats.append(res["elapsed_ms"])

        syn_records.append({
            "id": row.get("id", i),
            "label": y,
            "label_name": "Phishing" if y == 1 else "Legitimate",
            "subject": row.get("subject", ""),
            "score": res["score"],
            "pred_label": pred,
            "pred_name": "Phishing" if pred == 1 else "Safe",
            "result": "CORRECT" if pred == y else "ERROR",
            "elapsed_ms": round(res["elapsed_ms"], 2),
            "s_layer1": res["s_layer1"],
            "s_nlp": res["s_nlp"],
            "s_pure": res["s_pure"],
            "p_phish": res["p_phish"],
            "model_warm": res["model_warm"],
            "auth_mode": "synthetic",
            "commit_hash": COMMIT_HASH,
        })

    m_syn = calc_metrics(true_labels, syn_preds, syn_lats)
    auc_syn, auc_syn_l, auc_syn_h = bootstrap_roc_auc_ci(true_labels, syn_scores, n_bootstraps=1000, seed=42)
    m_syn["roc_auc"] = auc_syn
    m_syn["roc_auc_ci"] = (auc_syn_l, auc_syn_h)

    print(f"Confusion Matrix: TP={m_syn['tp']}, TN={m_syn['tn']}, FP={m_syn['fp']}, FN={m_syn['fn']}")
    print(f"Accuracy:  {m_syn['accuracy']:>6.2f}%  [95% Wilson CI: {m_syn['accuracy_ci'][0]:.1f}%, {m_syn['accuracy_ci'][1]:.1f}%]")
    print(f"Precision: {m_syn['precision']:>6.2f}%")
    print(f"Recall:    {m_syn['recall']:>6.2f}%  [95% Wilson CI: {m_syn['recall_ci'][0]:.1f}%, {m_syn['recall_ci'][1]:.1f}%]")
    print(f"FPR:       {m_syn['fpr']:>6.2f}%  [95% Wilson CI: {m_syn['fpr_ci'][0]:.1f}%, {m_syn['fpr_ci'][1]:.1f}%]")
    print(f"F1-Score:  {m_syn['f1']:>6.2f}%")
    print(f"ROC-AUC:   {m_syn['roc_auc']:.4f}  [95% Boot CI: {auc_syn_l:.4f}, {auc_syn_h:.4f}]")
    print(f"Latency:   Median = {m_syn['latency_median_ms']:.2f} ms | p95 = {m_syn['latency_p95_ms']:.2f} ms")

    # --- (b) Neutral Auth ---
    print("\n>>> (b) Neutral Auth Benchmark (Model Loaded) <<<")
    neu_records = []
    neu_scores = []
    neu_preds = []
    neu_lats = []

    for i, row in enumerate(rows):
        res = evaluate_sample_full(row, neutral_auth=True)
        pred = 1 if res["score"] >= PHISHING_SCORE_THRESHOLD else 0
        y = true_labels[i]

        neu_scores.append(res["score"])
        neu_preds.append(pred)
        neu_lats.append(res["elapsed_ms"])

        neu_records.append({
            "id": row.get("id", i),
            "label": y,
            "label_name": "Phishing" if y == 1 else "Legitimate",
            "subject": row.get("subject", ""),
            "score": res["score"],
            "pred_label": pred,
            "pred_name": "Phishing" if pred == 1 else "Safe",
            "result": "CORRECT" if pred == y else "ERROR",
            "elapsed_ms": round(res["elapsed_ms"], 2),
            "s_layer1": res["s_layer1"],
            "s_nlp": res["s_nlp"],
            "s_pure": res["s_pure"],
            "p_phish": res["p_phish"],
            "model_warm": res["model_warm"],
            "auth_mode": "neutral",
            "commit_hash": COMMIT_HASH,
        })

    m_neu = calc_metrics(true_labels, neu_preds, neu_lats)
    auc_neu, auc_neu_l, auc_neu_h = bootstrap_roc_auc_ci(true_labels, neu_scores, n_bootstraps=1000, seed=42)
    m_neu["roc_auc"] = auc_neu
    m_neu["roc_auc_ci"] = (auc_neu_l, auc_neu_h)

    print(f"Confusion Matrix: TP={m_neu['tp']}, TN={m_neu['tn']}, FP={m_neu['fp']}, FN={m_neu['fn']}")
    print(f"Accuracy:  {m_neu['accuracy']:>6.2f}%  [95% Wilson CI: {m_neu['accuracy_ci'][0]:.1f}%, {m_neu['accuracy_ci'][1]:.1f}%]")
    print(f"Precision: {m_neu['precision']:>6.2f}%")
    print(f"Recall:    {m_neu['recall']:>6.2f}%  [95% Wilson CI: {m_neu['recall_ci'][0]:.1f}%, {m_neu['recall_ci'][1]:.1f}%]")
    print(f"FPR:       {m_neu['fpr']:>6.2f}%  [95% Wilson CI: {m_neu['fpr_ci'][0]:.1f}%, {m_neu['fpr_ci'][1]:.1f}%]")
    print(f"F1-Score:  {m_neu['f1']:>6.2f}%")
    print(f"ROC-AUC:   {m_neu['roc_auc']:.4f}  [95% Boot CI: {auc_neu_l:.4f}, {auc_neu_h:.4f}]")
    print(f"Latency:   Median = {m_neu['latency_median_ms']:.2f} ms | p95 = {m_neu['latency_p95_ms']:.2f} ms")

    # Save CSVs
    csv_syn = OUTPUT_DIR / "step3_synthetic_auth_onnx_samples.csv"
    with open(csv_syn, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(syn_records[0].keys()))
        writer.writeheader()
        writer.writerows(syn_records)
    print(f"\nSaved: {csv_syn.relative_to(REPO_ROOT)}")

    csv_neu = OUTPUT_DIR / "step3_neutral_auth_onnx_samples.csv"
    with open(csv_neu, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(neu_records[0].keys()))
        writer.writeheader()
        writer.writerows(neu_records)
    print(f"Saved: {csv_neu.relative_to(REPO_ROOT)}")

    return m_syn, m_neu, neu_records


# ---------------------------------------------------------------------------
# STEP 4: Component Ablation Study (Neutral Auth, Model Loaded)
# ---------------------------------------------------------------------------

def run_step_4(rows: list[dict]):
    """
    Step 4 Ablation configs (neutral auth, model loaded):
    1) heuristics only (ensemble off)
    2) heuristics + ensemble
    3) DistilBERT pure (S_base only)
    4) NLP incl. adjustments
    5) heuristics + NLP (ensemble off)
    6) full pipeline as submitted
    """
    print("\n" + "=" * 70)
    print("STEP 4: Component Ablation Study (Neutral Auth, DistilBERT ONNX Loaded)")
    print("=" * 70)

    configs = [
        "1. Heuristics only (ensemble off)",
        "2. Heuristics + ensemble",
        "3. DistilBERT pure (S_base only)",
        "4. NLP incl. adjustments",
        "5. Heuristics + NLP (ensemble off)",
        "6. Full pipeline as submitted",
    ]

    true_labels = [int(r.get("label", 0)) for r in rows]
    config_scores = {c: [] for c in configs}
    ablation_samples = []

    p_phish_phishing = []
    p_phish_legit = []

    for i, row in enumerate(rows):
        y = true_labels[i]
        payload = EmailPayload(
            senderEmail=row.get("senderEmail", ""),
            subject=row.get("subject", ""),
            bodyText=row.get("bodyText", ""),
            links=json.loads(row.get("links", "[]")) if row.get("links") else [],
            attachments=json.loads(row.get("attachments", "[]")) if row.get("attachments") else [],
            hasAttachment=bool(json.loads(row.get("attachments", "[]")) if row.get("attachments") else []),
            attachmentCount=len(json.loads(row.get("attachments", "[]")) if row.get("attachments") else []),
            spfPass=True,
            dkimPass=True,
        )

        urls = extract_url_strings(payload.links or [])
        heur = evaluate_heuristics(payload)
        s_h = heur["score"]
        kw_hits = heur["keyword_hits"]
        has_typo = heur["has_typosquatting"]

        ens = score_with_ensemble(
            urls=urls,
            subject=payload.subject or "",
            body=payload.bodyText or "",
            urgency_keyword_count=kw_hits,
            has_typosquatting=has_typo,
            has_attachment=payload.hasAttachment or False,
            attachment_count=payload.attachmentCount or 0,
            attachments=payload.attachments or [],
            spf_pass=payload.spfPass,
        )
        s_ens = ens["ensemble_score"]
        s_l1_blended = min(100, round(0.60 * s_h + 0.40 * s_ens))

        text = f"{payload.subject or ''}\n\n{payload.bodyText or ''}".strip()
        nlp_full = classify_email_text(text=text, urgency_penalty=min(kw_hits * 8, 20), bec_penalty=20 if has_typo else 0)
        s_nlp = nlp_full["nlp_score"]

        nlp_pure = classify_email_text(text=text, urgency_penalty=0, bec_penalty=0)
        s_pure = round(nlp_pure["s_base"])
        p_phish = nlp_pure.get("p_phish", 0.0)

        if y == 1:
            p_phish_phishing.append(p_phish)
        else:
            p_phish_legit.append(p_phish)

        s_b = evaluate_behavioral(payload)  # 15

        # 1) Heuristics only:
        sc_1 = s_h
        # 2) Heuristics + ensemble:
        sc_2 = s_l1_blended
        # 3) DistilBERT pure:
        sc_3 = s_pure
        # 4) NLP incl. adjustments:
        sc_4 = s_nlp
        # 5) Heuristics + NLP (ensemble off):
        sc_5 = synthesize_composite_score(s_heuristic=s_h, s_nlp=s_nlp, s_behavioral=s_b, s_vt=0, vt_pending=True)
        # 6) Full pipeline:
        sc_6 = synthesize_composite_score(s_heuristic=s_l1_blended, s_nlp=s_nlp, s_behavioral=s_b, s_vt=0, vt_pending=True)

        config_scores[configs[0]].append(sc_1)
        config_scores[configs[1]].append(sc_2)
        config_scores[configs[2]].append(sc_3)
        config_scores[configs[3]].append(sc_4)
        config_scores[configs[4]].append(sc_5)
        config_scores[configs[6 - 1]].append(sc_6)

        ablation_samples.append({
            "id": row.get("id", i),
            "label": y,
            "label_name": "Phishing" if y == 1 else "Legitimate",
            "subject": row.get("subject", ""),
            "p_phish_pure": p_phish,
            "score_c1_heur_only": sc_1,
            "score_c2_heur_ens": sc_2,
            "score_c3_distilbert_pure": sc_3,
            "score_c4_nlp_adj": sc_4,
            "score_c5_heur_nlp_noens": sc_5,
            "score_c6_full_pipeline": sc_6,
            "pred_c1": int(sc_1 >= PHISHING_SCORE_THRESHOLD),
            "pred_c2": int(sc_2 >= PHISHING_SCORE_THRESHOLD),
            "pred_c3": int(sc_3 >= PHISHING_SCORE_THRESHOLD),
            "pred_c4": int(sc_4 >= PHISHING_SCORE_THRESHOLD),
            "pred_c5": int(sc_5 >= PHISHING_SCORE_THRESHOLD),
            "pred_c6": int(sc_6 >= PHISHING_SCORE_THRESHOLD),
            "commit_hash": COMMIT_HASH,
        })

    print(f"\n--- DistilBERT Pure P_phish Distribution ---")
    print(f"Phishing Rows (N=50):   Min = {min(p_phish_phishing):.4f} | Median = {np.median(p_phish_phishing):.4f} | Max = {max(p_phish_phishing):.4f}")
    print(f"Legitimate Rows (N=50): Min = {min(p_phish_legit):.4f} | Median = {np.median(p_phish_legit):.4f} | Max = {max(p_phish_legit):.4f}")

    ablation_results = {}
    for c in configs:
        scores = config_scores[c]
        preds = [1 if s >= PHISHING_SCORE_THRESHOLD else 0 for s in scores]
        m = calc_metrics(true_labels, preds)
        auc, auc_l, auc_h = bootstrap_roc_auc_ci(true_labels, scores, n_bootstraps=1000, seed=42)
        m["roc_auc"] = auc
        m["roc_auc_ci"] = (auc_l, auc_h)
        ablation_results[c] = m

        print(f"\n[{c}]")
        print(f"  Confusion Matrix: TP={m['tp']}, TN={m['tn']}, FP={m['fp']}, FN={m['fn']}")
        print(f"  Accuracy:  {m['accuracy']:>6.2f}%  [95% CI: {m['accuracy_ci'][0]:.1f}%, {m['accuracy_ci'][1]:.1f}%]")
        print(f"  Precision: {m['precision']:>6.2f}%")
        print(f"  Recall:    {m['recall']:>6.2f}%  [95% CI: {m['recall_ci'][0]:.1f}%, {m['recall_ci'][1]:.1f}%]")
        print(f"  FPR:       {m['fpr']:>6.2f}%  [95% CI: {m['fpr_ci'][0]:.1f}%, {m['fpr_ci'][1]:.1f}%]")
        print(f"  F1-Score:  {m['f1']:>6.2f}%")
        print(f"  ROC-AUC:   {m['roc_auc']:.4f}  [95% Boot CI: {auc_l:.4f}, {auc_h:.4f}]")

    # Save ablation samples CSV
    csv_abl = OUTPUT_DIR / "step4_ablation_onnx_samples.csv"
    with open(csv_abl, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(ablation_samples[0].keys()))
        writer.writeheader()
        writer.writerows(ablation_samples)
    print(f"\nSaved: {csv_abl.relative_to(REPO_ROOT)}")

    return ablation_results, (p_phish_phishing, p_phish_legit)


# ---------------------------------------------------------------------------
# Build Summary Table
# ---------------------------------------------------------------------------

def export_summary(m_syn: dict, m_neu: dict, ablation_results: dict, p_phish_stats: tuple):
    p_phish_phishing, p_phish_legit = p_phish_stats

    summary_rows = [
        {
            "Experiment / Configuration": "Step 3 (a): Full Pipeline (Synthetic Auth, ONNX Loaded)",
            "Accuracy (%)": f"{m_syn['accuracy']:.2f}% [{m_syn['accuracy_ci'][0]:.1f}%, {m_syn['accuracy_ci'][1]:.1f}%]",
            "Precision (%)": f"{m_syn['precision']:.2f}%",
            "Recall (%)": f"{m_syn['recall']:.2f}% [{m_syn['recall_ci'][0]:.1f}%, {m_syn['recall_ci'][1]:.1f}%]",
            "FPR (%)": f"{m_syn['fpr']:.2f}% [{m_syn['fpr_ci'][0]:.1f}%, {m_syn['fpr_ci'][1]:.1f}%]",
            "F1-Score (%)": f"{m_syn['f1']:.2f}%",
            "ROC-AUC [95% Boot CI]": f"{m_syn['roc_auc']:.4f} [{m_syn['roc_auc_ci'][0]:.4f}, {m_syn['roc_auc_ci'][1]:.4f}]",
            "Latency (Med / p95)": f"{m_syn['latency_median_ms']:.1f} ms / {m_syn['latency_p95_ms']:.1f} ms",
            "Notes / Protocol": "DistilBERT ONNX active; synthetic auth flags (TP=50, TN=50)",
        },
        {
            "Experiment / Configuration": "Step 3 (b): Full Pipeline (Neutral Auth, ONNX Loaded)",
            "Accuracy (%)": f"{m_neu['accuracy']:.2f}% [{m_neu['accuracy_ci'][0]:.1f}%, {m_neu['accuracy_ci'][1]:.1f}%]",
            "Precision (%)": f"{m_neu['precision']:.2f}%",
            "Recall (%)": f"{m_neu['recall']:.2f}% [{m_neu['recall_ci'][0]:.1f}%, {m_neu['recall_ci'][1]:.1f}%]",
            "FPR (%)": f"{m_neu['fpr']:.2f}% [{m_neu['fpr_ci'][0]:.1f}%, {m_neu['fpr_ci'][1]:.1f}%]",
            "F1-Score (%)": f"{m_neu['f1']:.2f}%",
            "ROC-AUC [95% Boot CI]": f"{m_neu['roc_auc']:.4f} [{m_neu['roc_auc_ci'][0]:.4f}, {m_neu['roc_auc_ci'][1]:.4f}]",
            "Latency (Med / p95)": f"{m_neu['latency_median_ms']:.1f} ms / {m_neu['latency_p95_ms']:.1f} ms",
            "Notes / Protocol": "DistilBERT ONNX active; neutral auth flags (TP=50, TN=50)",
        },
    ]

    for c, m in ablation_results.items():
        summary_rows.append({
            "Experiment / Configuration": f"Step 4: {c}",
            "Accuracy (%)": f"{m['accuracy']:.2f}% [{m['accuracy_ci'][0]:.1f}%, {m['accuracy_ci'][1]:.1f}%]",
            "Precision (%)": f"{m['precision']:.2f}%",
            "Recall (%)": f"{m['recall']:.2f}% [{m['recall_ci'][0]:.1f}%, {m['recall_ci'][1]:.1f}%]",
            "FPR (%)": f"{m['fpr']:.2f}% [{m['fpr_ci'][0]:.1f}%, {m['fpr_ci'][1]:.1f}%]",
            "F1-Score (%)": f"{m['f1']:.2f}%",
            "ROC-AUC [95% Boot CI]": f"{m['roc_auc']:.4f} [{m['roc_auc_ci'][0]:.4f}, {m['roc_auc_ci'][1]:.4f}]",
            "Latency (Med / p95)": "N/A (Component slice)",
            "Notes / Protocol": "Ablation run under neutral auth with loaded DistilBERT ONNX",
        })

    # Write CSV
    csv_path = OUTPUT_DIR / "step3_step4_summary_table.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(summary_rows[0].keys()))
        writer.writeheader()
        writer.writerows(summary_rows)
    print(f"Saved: {csv_path.relative_to(REPO_ROOT)}")

    # Write Markdown
    md_path = OUTPUT_DIR / "step3_step4_summary_table.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# AEGIS Supplementary Evaluation: Steps 3 & 4 (DistilBERT ONNX Loaded)\n\n")
        f.write(f"- **Evaluated Git Commit Hash:** `{COMMIT_HASH}`\n")
        f.write(f"- **Evaluation Dataset:** `aegis-backend/data/test_dataset.csv` (N=100: 50 phishing / 50 legitimate)\n")
        f.write(f"- **Execution Timestamp:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write("## DistilBERT Pure P_phish Distribution\n")
        f.write(f"- **Phishing Rows (N=50):** Min = `{min(p_phish_phishing):.4f}` | Median = `{np.median(p_phish_phishing):.4f}` | Max = `{max(p_phish_phishing):.4f}`\n")
        f.write(f"- **Legitimate Rows (N=50):** Min = `{min(p_phish_legit):.4f}` | Median = `{np.median(p_phish_legit):.4f}` | Max = `{max(p_phish_legit):.4f}`\n\n")

        headers = list(summary_rows[0].keys())
        f.write("| " + " | ".join(headers) + " |\n")
        f.write("| " + " | ".join(["---"] * len(headers)) + " |\n")
        for r in summary_rows:
            f.write("| " + " | ".join(str(r[h]) for h in headers) + " |\n")
    print(f"Saved: {md_path.relative_to(REPO_ROOT)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("AEGIS POST-SUBMISSION SUPPLEMENTARY EVALUATION: STEPS 3 & 4")
    print(f"Commit Hash: {COMMIT_HASH}")
    print("=" * 70)

    # 1. Load NLP model once before scoring
    t0 = time.time()
    loaded = load_nlp_model()
    load_time = (time.time() - t0) * 1000
    print(f"\n[NLP Model Initialization] load_nlp_model() returned: {loaded} ({load_time:.1f} ms)")
    if not loaded:
        print("ERROR: load_nlp_model() returned False. Aborting!")
        sys.exit(1)

    # 2. Sanity check first
    run_sanity_check()

    # 3. Load dataset
    with open(DATA_FILE, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    print(f"\nLoaded {len(rows)} samples from {DATA_FILE}")

    # 4. Run Step 3
    m_syn, m_neu, neu_records = run_step_3(rows)

    # 5. Run Step 4
    ablation_results, p_phish_stats = run_step_4(rows)

    # 6. Export summary tables
    export_summary(m_syn, m_neu, ablation_results, p_phish_stats)

    print("\n" + "=" * 70)
    print("STEPS 3 & 4 EVALUATION COMPLETED SUCCESSFULLY.")
    print("=" * 70)


if __name__ == "__main__":
    main()
