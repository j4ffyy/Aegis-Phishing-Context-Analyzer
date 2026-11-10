# Record of Artificial Intelligence Tool Usage (AI_USE.md)

**Project:** Aegis: AI-Powered Phishing Context Analyzer  
**Institutional Affiliation:** Mapúa Malayan Digital College (MMDC)  
**Capstone Program:** BS Information Technology (Capstone 1 & 2)  
**Document Generation Date:** 2026-11-09 (Updated Post-Defense Audit)  
**Specification:** Academic Integrity Disclosure & AI Usage Attribution  

---

## 1. Overview & Institutional Policy (MMDC AI Guidelines)

### Institutional Policy Statement
> **AI GUIDELINES MMDC:**  
> AI tools, and other resources that you can use to enhance the research, writing, organization, and presentation of your Capstone Project. Note, however, that AI and online resources should support, not replace, human analysis and problem-solving. When used responsibly and thoughtfully, these tools can improve the quality, accuracy, and efficiency of academic work while upholding integrity and ethical research practices.

In strict adherence to the institutional academic integrity standards and ethical research guidelines of Mapúa Malayan Digital College (MMDC), this document provides a comprehensive, transparent, and verifiable accounting of Artificial Intelligence (AI) tools, models, and generative assistants utilized across the project lifecycle.

Per repository auditing guidelines, all statements of provenance are strictly anchored to verifiable artifacts in Git history and repository files. Where specific tool sessions, model builds, or proprietary telemetry are not recorded in Git commit metadata, they are formally designated as **UNKNOWN**.

### Disclosure of AI Assistance in Document Structuring
In adherence to full academic transparency, the proponents disclose that **this disclosure document (`AI_USE.md`) itself was formatted and drafted with the assistance of an AI assistant during the post-defense audit**. 

Commercial and research AI assistants are governed by corporate usage policies and safety principles that explicitly forbid academic dishonesty, cheating, misrepresentation, and deceptive practices:
- **Anthropic Usage Policy:** Section on *Dishonest & Deceptive Practices* explicitly prohibits using the service to *"facilitate academic dishonesty, plagiarism, or cheat on evaluations"* ([Anthropic Usage Policy](https://www.anthropic.com/legal/commercial-terms)).
- **OpenAI Usage Policies:** Under *Deceptive or Misleading Practices*, explicitly prohibits activities that violate educational integrity, cheat on academic evaluations, or mislead individuals regarding the authenticity of academic submissions ([OpenAI Usage Policies](https://openai.com/policies/usage-policies)).
- **Google Generative AI Prohibited Use Policy:** Prohibits using the service to engage in *"fraud, scams, or other deceptive actions"* as well as misrepresentation, such as *"misrepresenting the provenance of generated content by claiming it was created solely by a human to deceive"* ([Google Generative AI Prohibited Use Policy](https://policies.google.com/terms/generative-ai/use-policy)), with explicit prohibitions against academic dishonesty appearing in Google Cloud enterprise agreements.

In accordance with these principles and MMDC guidelines, the assistance used to compile this document was strictly assistive: structuring disclosures, compiling Git history entries, and indexing verified SHA-256 evidence hashes. All factual assertions were reviewed and confirmed by the human proponents.

---

## 2. Itemized Ledger of Development Authorship, AI Tools, and Audit Agents

| Tool / Contributor Category | Primary Domain & Usage Scope | Specific Artifacts & Scope | Provenance & Git Verification Status |
|---|---|---|---|
| **Human Authorship (UI & Full-Stack Implementation)** | Frontend UI/UX, DOM Scripting, Core Systems Architecture | - All Chrome Extension UI/UX components (`dashboard.html`, `dashboard.js`, `overlay.html`, `overlay.js`)<br>- DOM-based Gmail email extraction (`content_script.js`)<br>- Backend architecture, API routing, and telemetry scrubbing (`analyze.py`)<br>- Core threat scoring and threshold mechanics (`modules/meta_classifier.py`) | **100% Human Implementation (`j4ffyy`)**.<br>*(All visual design, CSS styling, interactive preset toggles, DOM mutation observer handling, and system integration were designed and implemented directly by the proponents. AI coding assistants were restricted to minor syntax reference and boilerplate lookup).* |
| **Autonomous Evaluation & Auditing Agent (Antigravity)** | Post-Defense Code Auditing & Manifest Integrity Verification | - Post-defense automated evaluation execution (`tools/run_phase_c_evaluations.py`, `tools/run_round2_evaluations.py`)<br>- Evidence manifest & cryptographic checksum indexing (`tools/evidence_manifest.py`, `SHA256SUMS`, `EVIDENCE_INDEX.csv`)<br>- Forensic integrity audit documentation (`evidence/AUDIT_ROUND2.md` through `AUDIT_ROUND5.md`, `FINAL_INTEGRITY_REPORT.md`, `AI_USE.md`) | **Post-Defense Forensic Verification Only**.<br>*(Invoked strictly post-defense on November 8–10, 2026, to perform read-only static code audits, verify mathematical claims, test for potential label leakage, and reconcile evidence checksums per `AGENT_LOG.md`).* |
| **Commercial LLM (`claude.ai`)** | Synthetic Test Corpus Generation | - Authored 60 synthetic corporate benchmark emails (30 phishing lures, 30 legitimate workplace emails) without explicit keyword triggers (`evidence/E-43_llm-authored-eval/`) | **Verified in Repository Artifacts**.<br>*(Recorded as `"generator": "claude.ai"` in `E-43_llm_generation_prompts.json` on 2026-11-08; prompts, seed parameters, and evaluations preserved in full).* |
| **In-Editor Autocomplete (e.g. GitHub Copilot, Cursor)** | Minor In-Editor Syntax & Autocomplete | - Standard inline syntax completion in developer IDE | **UNKNOWN**.<br>*(Cannot be verified or disproven from Git commit metadata).* |

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

## 4. Academic Integrity, Human Verification & Ethics Statement

In alignment with the MMDC mandate that AI resources must *support, not replace, human analysis and problem-solving*, the proponents affirm the following governance controls:

- **Human Authorship & Architectural Authority:** All system architectures, core algorithmic formulations (multi-tier Bayesian weight allocation, circular behavioral distance, dual-trigger whitelist, and hard security threat floors), and defensive heuristics were formulated, reviewed, and finalized directly by the human proponents (**Jafphet P. Grengia** & **Michael Angelo L. Bernardo**).
- **Human Implementation of Extension and UI:** All frontend extension templates, styling, DOM listeners, and administrative dashboards were coded directly by the proponents. AI tools were not used to generate the user interface.
- **Independent Post-Defense Verification:** The autonomous auditing agent was employed as an external verification harness following the defense to cross-examine claims, check label leakage, verify cryptographic hashes, and ensure complete reproducibility of the evidence base.
- **Zero Runtime Generative AI Dependency:** The production Aegis Chrome extension and FastAPI backend **do not make calls to any external generative AI APIs (such as OpenAI, Anthropic, or Gemini) during live email analysis**. Live inference is 100% self-contained, offline-capable (via local ONNX Runtime), privacy-preserving, and non-reliant on cloud LLMs.
- **Empirical Grounding:** Every performance metric and confusion matrix presented in Chapter IV of the manuscript was produced by deterministic evaluation scripts executing against frozen, cryptographically hashed datasets (`SHA256SUMS`).
