# Model Card: Aegis DistilBERT Phishing Classifier (E-21 / I-07)

## 1. Model Details
- **Model Identifier (`model_id`):** `phishing_distilbert_onnx_4cls`
- **Base Architecture:** `DistilBertForSequenceClassification` (6 layers, 12 attention heads, hidden dimension 768, feed-forward dimension 3072, GELU activation)
- **Deployment Format:** ONNX Runtime (`CPUExecutionProvider`, float32)
- **Model Artifact Path:** `aegis-backend/models/phishing_distilbert/model.onnx`
- **Artifact Size:** 267,938,324 bytes (~255.52 MB)
- **Artifact SHA-256:** `361ebc80a1aa7f48778ad007abed802f93fc807ffbd741e8661cf3837c200db0`
- **Tokenizer:** `DistilBertTokenizer`
  - Vocabulary Size: 30,522 tokens (`bert-base-uncased` vocabulary)
  - Lowercase normalization: `do_lower_case = True`
  - Maximum sequence length: 512 tokens (truncated / padded with `pad_token_id = 0`)
  - Framework version: `transformers 4.57.6`

---

## 2. Intended Use & Pipeline Integration
- **Role in Aegis:** Layer 2 Semantic Intent Classifier.
- **Input:** Plain text concatenated from email subject and body (sanitized and scrubbed of PII via `pii_scrubber.js`).
- **Output:** 4-class softmax probability distribution:
  - Class 0 (`LABEL_0`): Legitimate email
  - Class 1 (`LABEL_1`): Phishing URL context
  - Class 2 (`LABEL_2`): Legitimate URL context
  - Class 3 (`LABEL_3`): Alternative phishing patterns
- **Scoring Formulation (§6.3):**
  $$\mathcal{P}_{\text{phish}} = P(\text{Class 1}) + P(\text{Class 3})$$
  $$S_{\text{base}} = \begin{cases} 60 \times \mathcal{P}_{\text{phish}} & \text{if } \mathcal{P}_{\text{phish}} > 0.50 \\ 10 \times (1 - \mathcal{P}_{\text{phish}}) & \text{otherwise} \end{cases}$$
  $$S_{\text{nlp}} = \min(100, \text{round}(S_{\text{base}} + S_{\text{urgency}} + S_{\text{bec}}))$$
- **Primary Domain:** Enterprise and SME desktop email triage (English-centric corporate correspondence).

---

## 3. Training & Provenance Verification
- **Model State:** Frozen static checkpoint. No real-time retraining or online continuous learning is active in deployment.
- **Feedback Loop:** `/api/v1/feedback` logs reported false positives and false negatives to memory (`_feedback_log`), but does not trigger checkpoint fine-tuning.
- **Training Data Provenance:** Fine-tuned on public phishing and legitimate email corpora prior to ONNX quantization/export.
- **Integrity Notice (Data Overlap):**
  - Because public phishing benchmarks share historical seeds (e.g. Nazario, SpamAssassin, Enron, CEAS), an exact overlap check against original pre-training splits cannot be cryptographically proven without the full raw pre-training archive.
  - Consequently, benchmark scores reported on synthetic evaluation datasets (`data/test_dataset.csv`) must be interpreted as laboratory validation metrics rather than zero-shot field generalizability.

---

## 4. Evaluation Performance & Known Limitations
- **Empirical Evaluation Summary:**
  - On synthetic evaluation sets with explicit phishing cues, $\mathcal{P}_{\text{phish}} > 0.995$ on all phishing test samples.
  - **Standalone False Positive Rate:** When evaluated in total isolation without heuristic layer suppression (Step 4 ablation), pure DistilBERT exhibits a **20.0% False Positive Rate (FPR)** on legitimate transactional notifications (e.g., invoices, PRN payment references, billing statements) due to lexical overlap with urgency cues.
  - **Ensemble Synergy:** Within the full 4-layer Aegis pipeline, Layer 1 heuristic checks (SPF/DKIM verification and whitelist matching) effectively suppress these false alarms, maintaining $FPR \le 2.0\%$.
- **Language Coverage Limitation:**
  - Standard uncased English BERT vocabulary (30,522 sub-word tokens).
  - Philippine multilingual context (Tagalog, Taglish, regional dialects) is processed via sub-word token fragmentation rather than dedicated language pre-training.
  - Dialectical and regional SME phishing variations require Layer 1 brand keywords and behavioral cues to ensure detection.

---

## 5. Deployment Constraints & Pre-warming Protocol
- **Memory Footprint:** Resident Set Size (RSS) during active ONNX CPU inference is $\approx 120\text{--}140\text{ MB}$, comfortably fitting within containerized environments (Render 512 MB memory ceiling).
- **Cold-Start Latency:** First-request cold loading of ONNX runtime session takes $\approx 1.2\text{--}1.8\text{ s}$. Subsequent warm inferences execute in $\approx 45\text{--}80\text{ ms}$.
- **Readiness Guard (I-02):** The `/api/v1/health` endpoint reports `model_loaded: true` only after `warm_up_nlp()` executes a dummy inference, preventing benchmark execution on unprimed sessions.
