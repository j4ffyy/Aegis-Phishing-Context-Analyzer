# Record of Artificial Intelligence Tool Usage (AI_USE.md)

**Project:** Aegis: AI-Powered Phishing Context Analyzer  
**Institutional Affiliation:** Mapúa Malayan Digital College (MMDC)  
**Capstone Program:** BS Information Technology (Capstone 1 & 2)  
**Document Generation Date:** 2026-11-09  
**Specification:** Academic Integrity Disclosure & AI Usage Attribution  

---

## 1. Overview & Disclosure Policy

In adherence to institutional academic integrity standards and ethical research guidelines, this document provides an honest accounting of Artificial Intelligence (AI) tools, models, and generative assistants utilized during the development, benchmarking, code evaluation, and documentation of the Aegis project.

Per repository auditing guidelines, all statements of provenance are strictly anchored to verifiable artifacts in Git history and repository files. Where specific tool sessions, model builds, or proprietary telemetry are not recorded in Git commit metadata, they are formally designated as **UNKNOWN**.

---

## 2. Itemized Ledger of AI Tools and Generative Agents

| AI Tool / Category | Primary Usage Domain | Specific Artifacts & Scope | Provenance & Git Verification Status |
|---|---|---|---|
| **AI Coding Assistants (Interactive Pair Programming)** | Interactive Code Assistance & Architecture Design | - Implementation Plan structuring (`implementation_plan.md`)<br>- Chrome Extension component layouts (`manifest.json`, `content_script.js`, `overlay.js`, `pii_scrubber.js`)<br>- Backend FastAPI routes and services (`routes/analyze.py`, `modules/meta_classifier.py`)<br>- UI adjustments (`dashboard.js`, `overlay.js`) | **Proponent Self-Disclosure**.<br>*(Specific model version and session IDs are **UNKNOWN in Git history**; Git commit logs record standard developer commits under `j4ffyy`).* |
| **Autonomous Evaluation & Auditing Agent (Antigravity)** | Evaluation Harnesses & Integrity Auditing | - Automated evaluation runners (`tools/run_phase_c_evaluations.py`, `tools/run_round2_evaluations.py`)<br>- Warning cut-off calibration script (`tools/calibrate_warning_cutoff.py`)<br>- Evidence manifest & checksum tools (`tools/evidence_manifest.py`)<br>- Integrity audit reports (`evidence/AUDIT_ROUND2.md` through `AUDIT_ROUND5.md`, `FINAL_INTEGRITY_REPORT.md`) | **Documented in repository dev logs**.<br>*(Traced to operator entries in `AGENT_LOG.md`).* |
| **Commercial LLM Session (External Corpus Generation)** | Synthetic Test Corpus Generation | - Authored 60 synthetic corporate emails (30 phishing lures, 30 legitimate workplace emails) without explicit keyword triggers (`evidence/E-43_llm-authored-eval/`) | **Model name as reported and not verified**.<br>*(Generated via external LLM evaluation harness on 2026-11-08; prompts preserved in `E-43_llm_generation_prompts.json`).* |
| **In-Editor Autocomplete (e.g. GitHub Copilot, Cursor)** | Minor In-Editor Syntax & Autocomplete | - Standard syntax completion in developer IDE | **UNKNOWN**.<br>*(Cannot be verified or disproven from Git commit metadata).* |

---

## 3. Embedded Machine Learning Models (Defensive System Components)

The following pre-trained or trained machine learning models serve as direct computational components of the Aegis defense pipeline (distinguished from generative development assistants):

1. **DistilBERT Sequence Classifier (Layer 2 Semantic Intent):**
   - **Base Checkpoint:** `lemonade-sdk/phishing-email-detection-distilbert-ONNX`
   - **Internal Model ID:** `phishing_distilbert_onnx_4cls`
   - **Artifact File:** `aegis-backend/models/phishing_distilbert/model.onnx`
   - **Artifact SHA-256:** `361ebc80a1aa7f48778ad007abed802f93fc807ffbd741e8661cf3837c200db0`
   - **Role:** Evaluates email subject and body text to generate a 4-class semantic probability distribution ($P_{\text{phish}} = P(1) + P(3)$). Operates locally via ONNX Runtime CPU execution.

2. **Ensemble ML Classifiers (Layer 1 Augmentation):**
   - **Random Forest Classifier:** Serialized at `aegis-backend/models/ensemble_rf.pkl`
   - **XGBoost Classifier:** Serialized at `aegis-backend/models/ensemble_xgb.pkl`
   - **Feature Vector:** 17 syntactic and structural features trained via `scripts/train_ensemble.py` on 1000 synthetic vectors (seed 42, 80/20 train/test split). Blended with heuristic rules ($0.60 \times S_{\text{heuristic}} + 0.40 \times S_{\text{ensemble}}$).

---

## 4. Academic Integrity & Ethics Statement

- **Human Authorship & Oversight:** All system designs, algorithmic formulations (weights, threat floors, behavioral circular distance, dual-trigger whitelist), and final revisions were directed and supervised by the project proponents (**Jafphet P. Grengia** & **Michael Angelo L. Bernardo**).
- **No Automated Unchecked Claims:** Every empirical performance metric reported in Chapter 4 of the manuscript and corresponding evidence artifacts was generated via deterministic scripts against frozen datasets and independently verified against source code.
