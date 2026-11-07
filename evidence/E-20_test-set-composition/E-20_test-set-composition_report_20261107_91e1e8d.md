# Test Dataset Composition & Source Audit Report (E-20)
- **Evidence ID:** `E-20`
- **Canonical Slug:** `test-set-composition`
- **Item:** `I-06` (Test-set audit and provenance)
- **Date (UTC):** `2026-11-07T15:03:54.702871+00:00`
- **Dataset File:** `aegis-backend/data/test_dataset.csv`
- **Dataset SHA-256:** `e278c6004a02e2935d83895d5e8242fcd8df50bc9b46641a10dc9ac6721f9254`
- **Commit:** `91e1e8d` (eval-freeze)

---

## 1. Dataset Overview

| Parameter | Value | Description |
| :--- | :--- | :--- |
| **Total Samples** | **100** | Controlled balanced benchmark test set |
| **Phishing Samples** | **50** | Curated targeting Philippine & international brands |
| **Legitimate Samples** | **50** | Genuine Philippine business, government, and internal templates |
| **Class Balance** | **50.0% / 50.0%** | Equal prior class probability |

---

## 2. Authentication Cue Analysis (Synthetic Label Contamination)

> [!WARNING] Synthetic Label Contamination Audit
> Analysis of `spfPass` and `dkimPass` confirms that **100% of phishing emails** were assigned synthetic `False/False` headers, while **100% of legitimate emails** were assigned `True/True` headers. This created an artificial 100% correlated feature cue in Layer 1 heuristics, causing benchmark recall to collapse from 86.0% down to 66.0% when authentication cues were neutralized (`--neutral-auth`).

| Class | Count | spfPass = False, dkimPass = False | spfPass = True, dkimPass = True | Indeterminate (None) |
| :--- | :--- | :--- | :--- | :--- |
| **Phishing** | 50 | **50 (100.0%)** | 0 (0.0%) | 0 (0.0%) |
| **Legitimate** | 50 | 0 (0.0%) | **50 (100.0%)** | 0 (0.0%) |

---

## 3. Brand Target Distribution

| Target Brand / Institution | Count | Domain Context / Representation |
| :--- | :--- | :--- |
| **BPI** | 18 | Targeted banking, e-commerce, government, or telco vectors |
| **GCash** | 17 | Targeted banking, e-commerce, government, or telco vectors |
| **BDO** | 16 | Targeted banking, e-commerce, government, or telco vectors |
| **Shopee** | 14 | Targeted banking, e-commerce, government, or telco vectors |
| **Lazada** | 9 | Targeted banking, e-commerce, government, or telco vectors |
| **Globe Telecom** | 6 | Targeted banking, e-commerce, government, or telco vectors |
| **Maya** | 5 | Targeted banking, e-commerce, government, or telco vectors |
| **SSS** | 5 | Targeted banking, e-commerce, government, or telco vectors |
| **PhilHealth** | 4 | Targeted banking, e-commerce, government, or telco vectors |
| **Other / General** | 4 | Targeted banking, e-commerce, government, or telco vectors |
| **Aegis Internal** | 2 | Targeted banking, e-commerce, government, or telco vectors |

---

## 4. Email Category Breakdown

| Functional Category | Class | Count | Primary Security Risk / Vector |
| :--- | :--- | :--- | :--- |
| **Transactional / Billing Notification** | Legitimate | 35 | Attack vector or benign business context |
| **Malicious Attachment Delivery** | Phishing | 18 | Attack vector or benign business context |
| **Account Suspension / Security Panic** | Phishing | 10 | Attack vector or benign business context |
| **Credential Harvesting** | Phishing | 10 | Attack vector or benign business context |
| **BEC / Wire Transfer Coercion** | Phishing | 8 | Attack vector or benign business context |
| **General Business Inquiry** | Legitimate | 7 | Attack vector or benign business context |
| **Routine Internal Communication** | Legitimate | 6 | Attack vector or benign business context |
| **Lottery / Reward Baiting** | Phishing | 4 | Attack vector or benign business context |
| **Company Newsletter / Update** | Legitimate | 2 | Attack vector or benign business context |

---

## 5. Language Breakdown

| Language Profile | Count | Proportion | Note |
| :--- | :--- | :--- | :--- |
| **English** | 81 | 81% | Standard business & threat correspondence |
| **Tagalog / Taglish** | 19 | 19% | Localized urgency cues evaluated by PR-06 Tagalog engine |

---

## 6. Audit Sign-Off

This breakdown rigorously characterizes the composition of the 100 benchmark samples, establishing transparent provenance for post-defense evaluations and addressing Revision Matrix Row 7, Row 8, Row 9, and Row 11.