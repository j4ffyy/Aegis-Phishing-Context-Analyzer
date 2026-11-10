"""
Verification of Offline NLP Execution Lifecycle
Branch: post-submission-eval
Commit Hash: 8c42233da6027148ccf0f735d7217b991d18bc3c
"""

import csv
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "aegis-backend"
DATA_FILE = BACKEND_DIR / "data" / "test_dataset.csv"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Emulate evaluate_models.py imports
from routes.analyze import (
    EmailPayload,
    evaluate_heuristics,
    evaluate_layer1,
    extract_url_strings,
)
from modules.nlp_classifier import classify_email_text, _session, _tokenizer, _model_warm

def main():
    print("=" * 70)
    print("VERIFICATION: evaluate_models.py Offline NLP Model State")
    print(f"Commit Hash: 8c42233da6027148ccf0f735d7217b991d18bc3c")
    print("=" * 70)

    print(f"\n[Global Module State at start]")
    print(f"  modules.nlp_classifier._session:   {_session}")
    print(f"  modules.nlp_classifier._tokenizer: {_tokenizer}")
    print(f"  modules.nlp_classifier._model_warm: {_model_warm}")

    with open(DATA_FILE, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))[:5]

    print(f"\n[Running original offline evaluation logic on first 5 samples]")
    all_false = True

    for i, row in enumerate(rows, 1):
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

        payload = EmailPayload(
            senderEmail=row.get("senderEmail", ""),
            subject=row.get("subject", ""),
            bodyText=row.get("bodyText", ""),
            links=links,
            attachments=attachments,
            hasAttachment=bool(attachments),
            attachmentCount=len(attachments),
            spfPass=str(row.get("spfPass", "True")).lower() == "true",
            dkimPass=str(row.get("dkimPass", "True")).lower() == "true",
        )

        urls = extract_url_strings(payload.links or [])
        layer1 = evaluate_layer1(payload, urls)
        kw_hits = layer1["keyword_hits"]
        has_typo = layer1.get("has_typosquatting", False)

        text = f"{payload.subject or ''}\n\n{payload.bodyText or ''}".strip()
        urgency_penalty = min(kw_hits * 8, 20)
        bec_penalty = 20 if has_typo else 0

        nlp_res = classify_email_text(
            text=text,
            urgency_penalty=urgency_penalty,
            bec_penalty=bec_penalty,
        )

        warm_flag = nlp_res.get("model_warm", None)
        if warm_flag is not False:
            all_false = False

        print(f"\nSample {i}: ID={row.get('id', '')} | Label={row.get('label', '')} ({'Phishing' if row.get('label')=='1' else 'Legitimate'})")
        print(f"  Subject:     {row.get('subject', '')[:60]}...")
        print(f"  model_warm:  {warm_flag}")
        print(f"  s_base:      {nlp_res.get('s_base')}")
        print(f"  s_urgency:   {nlp_res.get('s_urgency')}")
        print(f"  s_bec:       {nlp_res.get('s_bec')}")
        print(f"  nlp_score:   {nlp_res.get('nlp_score')}")

    print("\n" + "=" * 70)
    print(f"CONCLUSION: model_warm is False for ALL 5 samples: {all_false}")
    print("=" * 70)

if __name__ == "__main__":
    main()
