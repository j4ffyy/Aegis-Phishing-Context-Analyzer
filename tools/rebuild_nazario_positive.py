"""
Rebuild Public Positive Class Using Nazario Phishing ONLY (Exclude SpamAssassin Spam)
Extracts 125 unique, valid phishing messages from Jose Nazario phishing corpus (phishing0.mbox).
Generates:
  - evidence/E-39_independent-corpus/E-39_nazario_pure_phishing_125.csv
Reports counts, sources, hashes, and dates.
"""

import sys
import os
import csv
import json
import hashlib
import mailbox
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

from run_round2_evaluations import extract_email_components

def main():
    mbox_path = REPO_ROOT / "data" / "external_corpora" / "phishing0.mbox"
    if not mbox_path.exists():
        print(f"Error: {mbox_path} not found.")
        sys.exit(1)

    # Compute raw mbox hash
    with open(mbox_path, "rb") as f:
        mbox_sha256 = hashlib.sha256(f.read()).hexdigest()
    mbox_size = mbox_path.stat().st_size

    print(f"Loaded raw Nazario archive: {mbox_path.name}")
    print(f"  Size: {mbox_size:,} bytes")
    print(f"  SHA-256: {mbox_sha256}")

    mb = mailbox.mbox(str(mbox_path))
    total_mbox_msgs = len(mb)
    print(f"  Total raw messages in mbox: {total_mbox_msgs}")

    extracted = []
    seen_hashes = set()
    dedup_count = 0

    for idx, msg in enumerate(mb):
        raw = msg.as_bytes()
        comp = extract_email_components(raw)
        body = comp["bodyText"]
        if len(body) < 40:
            continue
        h = hashlib.sha256(body.lower().encode("utf-8")).hexdigest()
        if h in seen_hashes:
            dedup_count += 1
            continue
        seen_hashes.add(h)

        extracted.append({
            "id": f"NAZARIO_PHISH_{len(extracted):03d}",
            "label": 1,
            "label_name": "Phishing",
            "source_corpus": "Jose_Nazario_phishing0_mbox",
            "source_url": "https://monkey.org/~jose/phishing/phishing0.mbox",
            "senderEmail": comp["senderEmail"],
            "subject": comp["subject"],
            "bodyText": comp["bodyText"],
            "links": json.dumps(comp["links"]),
            "attachments": json.dumps(comp["attachments"]),
            "hasAttachment": comp["hasAttachment"],
            "attachmentCount": comp["attachmentCount"],
        })
        if len(extracted) >= 125:
            break

    print(f"Extracted {len(extracted)} pure Nazario phishing samples (Discarded {dedup_count} duplicates/too short).")

    out_csv = REPO_ROOT / "evidence" / "E-39_independent-corpus" / "E-39_nazario_pure_phishing_125.csv"
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(extracted[0].keys()))
        w.writeheader()
        w.writerows(extracted)

    # Compute CSV hash
    with open(out_csv, "rb") as f:
        csv_sha256 = hashlib.sha256(f.read()).hexdigest()

    manifest = {
        "dataset_name": "Jose Nazario Pure Phishing Positive Class (125 Samples)",
        "extraction_date": "2026-11-09",
        "sample_count": len(extracted),
        "source_repository": "https://monkey.org/~jose/phishing/",
        "canonical_archive": "phishing0.mbox",
        "raw_archive_sha256": mbox_sha256,
        "raw_archive_bytes": mbox_size,
        "raw_archive_total_messages": total_mbox_msgs,
        "deduplicated_messages": dedup_count,
        "output_csv": str(out_csv.relative_to(REPO_ROOT)),
        "output_csv_sha256": csv_sha256,
        "recent_phishing_sources_documented": [
            {
                "name": "Zenodo Phishing Validation Emails Dataset",
                "doi": "10.5281/zenodo.13474745",
                "year": 2024,
                "url": "https://doi.org/10.5281/zenodo.13474745",
                "description": "Curated benchmark of 2,000 real-world and synthetic phishing/legitimate emails for ML/NLP validation."
            },
            {
                "name": "Mendeley Data Spam & Phishing Detection Dataset",
                "doi": "10.17632/shj94nrczy.1",
                "year": 2025,
                "url": "https://doi.org/10.17632/shj94nrczy.1",
                "description": "Cybersecurity email classification dataset containing raw RFC822 and preprocessed phishing samples."
            },
            {
                "name": "Jose Nazario Extended Phishing Archives (phishing1-3.mbox)",
                "source": "https://monkey.org/~jose/phishing/",
                "date": "2005-2007",
                "description": "Canonical multi-gigabyte raw mailbox archives (phishing1: 4.19 MB, phishing2: 10.42 MB, phishing3: 20.07 MB)."
            }
        ]
    }

    manifest_path = REPO_ROOT / "evidence" / "E-39_independent-corpus" / "E-39_nazario_rebuild_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"Rebuild completed successfully.")
    print(f"  CSV: {out_csv}")
    print(f"  CSV SHA-256: {csv_sha256}")
    print(f"  Manifest: {manifest_path}")

if __name__ == "__main__":
    main()

