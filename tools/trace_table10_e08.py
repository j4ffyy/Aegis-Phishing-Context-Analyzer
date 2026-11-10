"""
Trace TC-01 to TC-03 Directly from Phase C Per-Sample CSV (E-08, Model Loaded)
Ground-truth trace linking test cases to exact predictions in E-08 and test_dataset.csv.
"""

import csv
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

def main():
    e08_csv = REPO_ROOT / "evidence" / "E-08_phishing-corpus-metrics" / "E-08_phishing-corpus-metrics_predictions_20261108_0c541f5.csv"
    test_csv = REPO_ROOT / "aegis-backend" / "data" / "test_dataset.csv"

    with open(e08_csv, "r", encoding="utf-8") as f:
        e08_rows = {r["id"]: r for r in csv.DictReader(f)}

    with open(test_csv, "r", encoding="utf-8") as f:
        test_rows = {r["id"]: r for r in csv.DictReader(f)}

    cases = [
        ("TC-01", "50", "Legitimate Workplace Newsletter"),
        ("TC-02", "37", "Phishing Urgent Suspension Lure"),
        ("TC-03", "24", "Phishing Credential / Order Hold Lure"),
    ]

    results = []

    print("=" * 80)
    print("TABLE 10 TRACE FROM PHASE C PER-SAMPLE CSV (E-08, MODEL LOADED)")
    print("=" * 80)

    for tc_id, s_id, desc in cases:
        e08 = e08_rows[s_id]
        raw = test_rows[s_id]

        record = {
            "test_case_id": tc_id,
            "sample_id": int(s_id),
            "description": desc,
            "provenance_file": "evidence/E-08_phishing-corpus-metrics/E-08_phishing-corpus-metrics_predictions_20261108_0c541f5.csv",
            "model_state": "DistilBERT ONNX Loaded (Warm)",
            "subject": e08["subject"],
            "senderEmail": e08["senderEmail"],
            "true_label": int(e08["label"]),
            "true_label_name": e08["label_name"],
            "composite_score": int(e08["score"]),
            "assigned_risk_tier": e08["risk_level"],
            "distilbert_p_phish": float(e08["p_phish"]),
            "layer2_s_nlp": int(e08["s_nlp"]),
            "inference_latency_ms": float(e08["elapsed_ms"]),
            "predicted_phishing": int(e08["predicted_phishing"]),
            "body_snippet": raw.get("bodyText", "")[:120],
            "links": json.loads(raw["links"]) if raw.get("links") else [],
            "attachments": json.loads(raw["attachments"]) if raw.get("attachments") else [],
            "spf_pass": raw.get("spfPass"),
            "dkim_pass": raw.get("dkimPass"),
            "test_verdict": "PASS (Correctly Classified)" if (int(e08["label"]) == int(e08["predicted_phishing"])) else "FAIL"
        }
        results.append(record)

        print(f"\n[{tc_id}] {desc} (Sample ID: {s_id})")
        print(f"  Source CSV:       {record['provenance_file']}")
        print(f"  Subject:          {record['subject']}")
        print(f"  Sender:           {record['senderEmail']}")
        print(f"  Ground Truth:     {record['true_label_name']} (Label={record['true_label']})")
        print(f"  Composite Score:  {record['composite_score']}/100")
        print(f"  Risk Tier:        {record['assigned_risk_tier']}")
        print(f"  NLP Prob P(phish):{record['distilbert_p_phish']}")
        print(f"  NLP Score S_nlp:  {record['layer2_s_nlp']}")
        print(f"  Latency:          {record['inference_latency_ms']} ms")
        print(f"  Outcome:          {record['test_verdict']}")

    out_file = REPO_ROOT / "evidence" / "E-45_small-fixes" / "E-45_table10_trace_e08.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nTrace saved to: {out_file}")

if __name__ == "__main__":
    main()

