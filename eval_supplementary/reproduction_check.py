"""
Supplementary Evaluation: Step 1 Reproduction Check
Branch: post-submission-eval
Commit Hash: 8c42233da6027148ccf0f735d7217b991d18bc3c
"""

import csv
import json
import os
import sys
import time
from pathlib import Path

# Paths
REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "aegis-backend"
DATA_FILE = BACKEND_DIR / "data" / "test_dataset.csv"
OUTPUT_DIR = REPO_ROOT / "evidences" / "supplementary"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

COMMIT_HASH = "8c42233da6027148ccf0f735d7217b991d18bc3c"

# Add backend to path
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from routes.analyze import (
    EmailPayload,
    evaluate_layer1,
    evaluate_nlp_intent,
    evaluate_behavioral,
    extract_url_strings,
)
from modules.meta_classifier import synthesize_composite_score

PHISHING_SCORE_THRESHOLD = 45


def evaluate_sample(row, neutral_auth=False):
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
    s_heuristic = layer1["score"]
    s_nlp = evaluate_nlp_intent(payload, layer1["keyword_hits"], layer1.get("has_typosquatting", False))
    s_behavioral = evaluate_behavioral(payload)
    score = synthesize_composite_score(
        s_heuristic=s_heuristic,
        s_nlp=s_nlp,
        s_behavioral=s_behavioral,
        s_vt=0,
        vt_pending=True,
    )
    elapsed_ms = (time.time() - t_start) * 1000
    return score, elapsed_ms, s_heuristic, s_nlp, s_behavioral


def run_benchmark(neutral_auth=False):
    with open(DATA_FILE, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    true_labels = []
    pred_labels = []
    scores = []
    records = []

    for row in rows:
        true_label = int(row.get("label", 0))
        score, elapsed, s_h, s_nlp, s_b = evaluate_sample(row, neutral_auth=neutral_auth)
        pred_label = 1 if score >= PHISHING_SCORE_THRESHOLD else 0

        true_labels.append(true_label)
        pred_labels.append(pred_label)
        scores.append(score)

        records.append({
            "id": row.get("id", ""),
            "label": true_label,
            "label_name": "Phishing" if true_label == 1 else "Legitimate",
            "senderEmail": row.get("senderEmail", ""),
            "subject": row.get("subject", ""),
            "score": score,
            "pred_label": pred_label,
            "pred_name": "Phishing" if pred_label == 1 else "Safe",
            "result": "CORRECT" if pred_label == true_label else "ERROR",
            "elapsed_ms": round(elapsed, 2),
            "s_layer1": s_h,
            "s_nlp": s_nlp,
            "s_behavioral": s_b,
            "auth_mode": "neutral" if neutral_auth else "synthetic",
            "commit_hash": COMMIT_HASH,
        })

    tp = sum(1 for t, p in zip(true_labels, pred_labels) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(true_labels, pred_labels) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(true_labels, pred_labels) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(true_labels, pred_labels) if t == 1 and p == 0)

    n = len(true_labels)
    acc = (tp + tn) / n * 100
    prec = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0.0
    f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
    fpr = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0.0

    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "fpr": fpr,
        "records": records,
    }


def main():
    print(f"AEGIS Reproduction Check on Commit: {COMMIT_HASH}")
    print("=" * 60)

    # 1. Synthetic Auth
    print("\n--- Running (a) Synthetic Auth Benchmark ---")
    res_syn = run_benchmark(neutral_auth=False)
    print(f"Observed: TP={res_syn['tp']} TN={res_syn['tn']} FP={res_syn['fp']} FN={res_syn['fn']}")
    print(f"Metrics:  Accuracy={res_syn['accuracy']:.2f}%, Precision={res_syn['precision']:.2f}%, "
          f"Recall={res_syn['recall']:.2f}%, FPR={res_syn['fpr']:.2f}%, F1={res_syn['f1']:.2f}%")

    # 2. Neutral Auth
    print("\n--- Running (b) Neutral Auth Benchmark ---")
    res_neu = run_benchmark(neutral_auth=True)
    print(f"Observed: TP={res_neu['tp']} TN={res_neu['tn']} FP={res_neu['fp']} FN={res_neu['fn']}")
    print(f"Metrics:  Accuracy={res_neu['accuracy']:.2f}%, Precision={res_neu['precision']:.2f}%, "
          f"Recall={res_neu['recall']:.2f}%, FPR={res_neu['fpr']:.2f}%, F1={res_neu['f1']:.2f}%")

    # Save outputs
    # Synthetic samples CSV
    csv_syn = OUTPUT_DIR / "reproduction_check_synthetic_samples.csv"
    with open(csv_syn, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(res_syn["records"][0].keys()))
        writer.writeheader()
        writer.writerows(res_syn["records"])

    # Neutral samples CSV
    csv_neu = OUTPUT_DIR / "reproduction_check_neutral_samples.csv"
    with open(csv_neu, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(res_neu["records"][0].keys()))
        writer.writeheader()
        writer.writerows(res_neu["records"])

    # Save summary report txt
    log_file = OUTPUT_DIR / "reproduction_check_log.txt"
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(f"AEGIS Reproduction Check Log\n")
        f.write(f"Commit Hash: {COMMIT_HASH}\n")
        f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("--- (a) Synthetic Auth Benchmark ---\n")
        f.write(f"Confusion Matrix: TP={res_syn['tp']}, TN={res_syn['tn']}, FP={res_syn['fp']}, FN={res_syn['fn']}\n")
        f.write(f"Accuracy: {res_syn['accuracy']:.2f}%, Precision: {res_syn['precision']:.2f}%, Recall: {res_syn['recall']:.2f}%, FPR: {res_syn['fpr']:.2f}%, F1: {res_syn['f1']:.2f}%\n\n")
        f.write("--- (b) Neutral Auth Benchmark ---\n")
        f.write(f"Confusion Matrix: TP={res_neu['tp']}, TN={res_neu['tn']}, FP={res_neu['fp']}, FN={res_neu['fn']}\n")
        f.write(f"Accuracy: {res_neu['accuracy']:.2f}%, Precision: {res_neu['precision']:.2f}%, Recall: {res_neu['recall']:.2f}%, FPR: {res_neu['fpr']:.2f}%, F1: {res_neu['f1']:.2f}%\n")

    # Verification Checks
    syn_expected = (43, 50, 0, 7)
    neu_expected = (33, 50, 0, 17)

    syn_actual = (res_syn['tp'], res_syn['tn'], res_syn['fp'], res_syn['fn'])
    neu_actual = (res_neu['tp'], res_neu['tn'], res_neu['fp'], res_neu['fn'])

    print("\n" + "=" * 60)
    print("VERIFICATION RESULT:")
    syn_pass = (syn_actual == syn_expected)
    neu_pass = (neu_actual == neu_expected)

    print(f"(a) Synthetic Auth: Expected {syn_expected} -> Actual {syn_actual} : {'PASS' if syn_pass else 'FAIL'}")
    print(f"(b) Neutral Auth:   Expected {neu_expected} -> Actual {neu_actual} : {'PASS' if neu_pass else 'FAIL'}")

    if syn_pass and neu_pass:
        print("\nALL REPRODUCTION CHECKS PASSED EXACTLY.")
        sys.exit(0)
    else:
        print("\nREPRODUCTION CHECK FAILED!")
        sys.exit(1)


if __name__ == "__main__":
    main()
