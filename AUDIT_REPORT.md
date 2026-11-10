# AEGIS POST-DEFENSE REPOSITORY AUDIT REPORT (AUDIT_REPORT.md)

**Audit Execution Date:** 2026-11-09  
**Repository Root:** `c:\Users\jafph\Desktop\Capstone 1 - Phishing Analyzer\Aegis-Phishing-Context-Analyzer`  
**Git HEAD Commit:** `dede10130f9ced052c7f241ac1c5d19e972cc3bb` (Tagged `v1.0-capstone-submission`)  
**Audit Standard:** Zero modification of source/data/evidence files; strict citations with file paths, line numbers, and command outputs; unverified claims designated as "NOT FOUND".

---

## 1. MODEL-LOADED GUARD

### 1.a) Evaluation Scripts Identification
The evaluation scripts across all phases and supplementary evaluation modules in the repository are:

1. **Phase C Full-Suite Runner (Phase C, Ablation, Threshold Sweep, E-08, E-09):**  
   `tools/run_phase_c_evaluations.py` (Lines 268–475)
2. **Round 2 Supplementary Evaluation Runner (Public corpora E-39, Philippine/Taglish E-42, LLM-authored E-43, Transactional E-34, Ensemble investigation E-41):**  
   `tools/run_round2_evaluations.py` (Lines 1770–1874)
3. **Round 3 Warning Cut-Off Calibration on 200-Train Split:**  
   `tools/calibrate_warning_cutoff.py` (Lines 20–150)
4. **4-Set Calibrated Threshold Evaluator:**  
   `tools/evaluate_all_sets_calibrated.py` (Lines 20–139)
5. **Pure Nazario Holdout Evaluation Script:**  
   `tools/evaluate_nazario_only.py` (Lines 20–116)
6. **Backend Standalone Evaluation Script:**  
   `aegis-backend/scripts/evaluate_models.py` (Lines 410–540)
7. **Supplementary Stress & Clean Domain Evaluation Scripts:**  
   - `eval_supplementary/evaluate_step5e.py` (Lines 140–180)
   - `eval_supplementary/evaluate_with_onnx.py` (Lines 660–690)
   - `eval_supplementary/evaluate_steps_5_6.py` (Lines 165–200)

---

### 1.b) Abort Guard Status Per Script (Loaded AND Warm)
A script has a valid loaded-and-warm abort guard only if it verifies both that ONNX model weights are loaded (`_session is not None`) AND that the model is warm (`is_model_warm() is True`), aborting execution (`sys.exit`) if either check fails:

| Evaluation Script | Model Priming Call | Abort Guard Present? | Does it abort unless DistilBERT reports loaded AND warm? | Exact Code / Citations |
|---|---|:---:|:---:|---|
| `tools/run_phase_c_evaluations.py` | `load_nlp_model()` | Partial | **NO** | Lines 276–282 check `if not is_model_warm(): loaded = load_nlp_model(); if not loaded: sys.exit(...)`. However, `load_nlp_model()` only loads `_session` and `_tokenizer`; it does **not** call `warm_up_nlp()`, leaving `_model_warm = False`. The script prints `is_model_warm()` (which evaluates to `False`), but does not abort on `not is_model_warm()`. At line 338, it hardcodes `"model_loaded": True`. |
| `tools/run_round2_evaluations.py` | `warm_up_nlp()` | **YES** (Current) / **NO** (Original) | **YES** (at current HEAD) | In commit `95c6d12` (original Round 2), line 1777 called `load_nlp_model()` with **no abort guard**. At current HEAD (`ad02e33` / `dede101`), lines 1779–1782 call `warm_up_nlp()` followed by: `if not is_model_warm(): print("FATAL: DistilBERT model reports warm=False. Evaluation harness aborted."); sys.exit(1)`. |
| `tools/calibrate_warning_cutoff.py` | `warm_up_nlp()` | **YES** (Current) / **NO** (Original) | **YES** (at current HEAD) | In commit `19affee` (original Round 3), lines 23–28 called neither `load_nlp_model()` nor `warm_up_nlp()`, running in fallback mode with **no guard**. In current commit `ad02e33`, lines 25–28 call `warm_up_nlp()` followed by `if not is_model_warm(): sys.exit(1)`. |
| `tools/evaluate_nazario_only.py` | `warm_up_nlp()` | **YES** | **YES** | Lines 25–28 execute `warm_up_nlp()` and explicitly guard: `if not is_model_warm(): sys.exit(1)`. |
| `tools/evaluate_all_sets_calibrated.py` | None | N/A | **NO** | Offline re-evaluation script that parses pre-computed prediction CSVs (`E-39_predictions_full_standard.csv`, `E-43_llm_predictions.csv`, etc.). No model inference is executed. |
| `aegis-backend/scripts/evaluate_models.py` | `warm_up_nlp()` | Conditional | **CONDITIONAL** | Lines 414–425 enforce guard only when `args.check_model` is enabled (default `True`): `if not is_model_warm(): warm_up_nlp(); if not is_model_warm(): sys.exit(1)`. If run with `--no-check-model`, it does not abort. |
| `eval_supplementary/evaluate_step5e.py` | `load_nlp_model()` | None | **NO** | Line 145 calls `loaded = load_nlp_model()`, but does not warm up or abort if `not is_model_warm()`. |
| `eval_supplementary/evaluate_with_onnx.py` | `load_nlp_model()` | Partial | **NO** | Lines 661–665 verify `if not loaded: sys.exit()`, but do not verify `is_model_warm()`. |

---

### 1.c) Forensic Audit of Round 2 `model_loaded = false`
1. **Exact File and Line:**  
   `evidence/E-39_round2_master_summary.json`, **Line 394**:
   ```json
   394:       "model_loaded": false,
   395:       "commit": "95c6d12",
   396:       "date": "2026-11-08"
   ```
2. **Warm-Up Flag Involved:**  
   The module-level variable `_model_warm` in `aegis-backend/modules/nlp_classifier.py`:
   - Line 83: `global _session, _tokenizer, _model_warm`
   - Lines 95, 127: Set to `_model_warm = False` during initialization/failure.
   - Line 148: Set to `_model_warm = True` **only** inside `warm_up_nlp()`.
   - Lines 155–157: `is_model_warm()` returns `_model_warm`.
   - Originating logging code: `tools/run_round2_evaluations.py:848`: `"model_loaded": is_model_warm()`.
3. **Real Model Outputs vs Fallback Values (Score Distribution):**  
   - In commit `95c6d12`, line 1777 called `load_nlp_model()`.
   - In `aegis-backend/modules/nlp_classifier.py:198–199`, fallback routing occurs **only** when `_session is None or _tokenizer is None`. Because `load_nlp_model()` successfully initialized the ONNX `InferenceSession` and HuggingFace Rust tokenizer into memory, `classify_email_text()` executed **genuine ONNX model forward inference passes**.
   - Inspection of `evidence/E-39_independent-corpus/E-39_predictions_full_standard.csv` confirms real model probability outputs in column `s_nlp`:
     - Unique `s_nlp` values: 6 distinct values (`10, 34, 57, 60, 68, 76`).
     - Distribution summary: Min = 10, Mean = 38.62, Median = 45.5, Max = 76.
     - Fallback scores generated by `_fallback_classification()` (`aegis-backend/modules/nlp_classifier.py:274`) produce flat values based solely on length: `base = 20 if len(text) > 100 else 10`. The observed continuous float-derived scores ($S_{\text{base}} = 60 \times P_{\text{phish}}$) confirm that **Round 2 executed genuine DistilBERT model weights, NOT fallback values**.

---

### 1.d) Smallest Change to Make Round 2 Log `model_loaded = true`
Without editing code yet, the smallest single-line change is:
- **In `tools/run_round2_evaluations.py`, Line 1777 (commit `95c6d12`):**  
  Change `load_nlp_model()` to `warm_up_nlp()`.  
  *Reason:* `warm_up_nlp()` loads the model session and tokenizer, runs a dummy forward pass, and sets `_model_warm = True`. At line 848, `"model_loaded": is_model_warm()` will then evaluate to `True`.

---

## 2. NAZARIO / PUBLIC-CORPUS ARITHMETIC

### 2.a) 50-Email Public Test Split Breakdown
Direct inspection of `evidence/E-39_independent-corpus/E-39_dataset_test_50.csv`:
- Total test split samples: $N = 50$ (25 phishing positives, 25 legitimate negatives).
- Breakdown of the 25 positive samples (`label == 1`):
  - **Jose Nazario Phishing Corpus (`Nazario_phishing0`):** **14 samples** (IDs: `TEST_000, TEST_001, TEST_002, TEST_004, TEST_008, TEST_010, TEST_011, TEST_014, TEST_015, TEST_018, TEST_021, TEST_022, TEST_023, TEST_049`).
  - **SpamAssassin Spam Corpus (`SpamAssassin_spam`):** **11 samples** (IDs: `TEST_007, TEST_009, TEST_012, TEST_013, TEST_016, TEST_017, TEST_019, TEST_020, TEST_024, TEST_035, TEST_037`).
- Command verification:
  ```python
  import pandas as pd
  df = pd.read_csv('evidence/E-39_independent-corpus/E-39_dataset_test_50.csv')
  df[df['label'] == 1]['source_corpus'].value_counts()
  # Nazario_phishing0: 14, SpamAssassin_spam: 11
  ```
- **Finding:** The paper’s statement of 14 Nazario + 11 generic spam is **verified and exactly correct**.

---

### 2.b) Nazario-Only Set (25 Phishing + 25 Legit) Provenance & Overlap Reconciliation
The pure Nazario test split is constructed in `tools/evaluate_nazario_only.py:47–51` by taking a seed 42 shuffle of `evidence/E-39_independent-corpus/E-39_nazario_pure_phishing_125.csv` and selecting holdout slice `[100:125]`.

We evaluated the SHA-256 body hash of all 25 Nazario test positives against the original E-39 test and train splits:
- **Overlap with E-39 Test Split (`E-39_dataset_test_50.csv`):** **4 samples**
- **Overlap with E-39 Training Split (`E-39_dataset_train_200.csv`):** **9 samples**
- **Neither (Completely new Nazario samples not present in E-39):** **12 samples**
- **Total Nazario Positives:** $4 + 9 + 12 = 25$ samples.
- **Reconciliation:** The paper correctly discloses that **9 samples overlap the training split by hash** ($9 / 25 = 36.0\%$ contamination). The remaining 16 samples consist of 4 samples from the original test split and 12 newly sampled Nazario lures. The 25 legitimate ham samples are 100% sourced from the test split (`E-39_dataset_test_50.csv`).

---

### 2.c) Nazario-Only Fallback Rerun Location & Status
- **Location:** `evidence/AUDIT_ROUND4.md`, Lines 60–73 (Item 2.b), evaluated under commit `19affee`.
- **Logged Status in Round 4:** Evaluated with `warm=False` (fallback mode). Reported metrics at $T=45$: 8 TP, 0 FP, 25 TN, 17 FN (Recall 32.0%, FPR 0.0%).
- **Forensic Diagnosis:** In Round 4, the evaluator copied the confusion matrix directly from `E-39_predictions_full_standard.csv` (the mixed 14 Nazario + 11 SpamAssassin test set) rather than evaluating pure Nazario.
- **Superseded Status in Round 5:** Formally rerun with DistilBERT verified warm (`model_loaded: true`) in `tools/evaluate_nazario_only.py` and serialized to `evidence/E-39_independent-corpus/nazario_only_eval.json` and `evidence/AUDIT_ROUND5.md:120–132`:
  - At $T=45$ (Production): **3 TP, 0 FP, 25 TN, 22 FN** $\rightarrow$ **Recall = 12.0%** [95% CI: 4.2, 30.0]%, FPR = 0.0%, Precision = 100.0%, F1 = 21.43%, ROC-AUC = 0.992.
  - At $T=25$ (Calibrated Zero-FPR): **24 TP, 0 FP, 25 TN, 1 FN** $\rightarrow$ **Recall = 96.0%** [95% CI: 80.5, 99.3]%, FPR = 0.0%, Precision = 100.0%, F1 = 97.96%, ROC-AUC = 0.992.
  - At $T=20$ (Youden): **24 TP, 1 FP, 24 TN, 1 FN** $\rightarrow$ **Recall = 96.0%**, FPR = 4.0%, Precision = 96.0%, F1 = 96.00%, ROC-AUC = 0.992.

---

## 3. ENSEMBLE REMOVAL TEST

### 3.a) Computation of $S_{\text{layer1\_final}} = 0.60 \times S_{\text{heuristic}} + 0.40 \times S_{\text{ensemble}}$
1. **Source Code Implementation:**  
   `aegis-backend/routes/analyze.py`, Lines 389–418:
   ```python
   heuristics = evaluate_heuristics(payload)
   s_heuristic = heuristics["score"]

   ensemble_result = score_with_ensemble(
       urls=urls,
       subject=payload.subject or "",
       body=payload.bodyText or "",
       urgency_keyword_count=heuristics["keyword_hits"],
       has_typosquatting=heuristics["has_typosquatting"],
       has_attachment=payload.hasAttachment or False,
       attachment_count=payload.attachmentCount or 0,
       attachments=payload.attachments or [],
       spf_pass=payload.spfPass,
   )

   ensemble_used = ensemble_result["ensemble_used"]
   s_ensemble = ensemble_result["ensemble_score"]

   if ensemble_used:
       blended = round(0.60 * s_heuristic + 0.40 * s_ensemble)
       s_layer1 = min(100, blended)
   else:
       s_layer1 = s_heuristic
   ```
2. **Ensemble Sub-Score Computation:**  
   `aegis-backend/modules/ensemble_classifier.py`, Lines 242–308:
   - Evaluates a 17-element syntactic feature vector.
   - Averages Random Forest and XGBoost probabilities: `avg_prob = 0.5 * (rf_phish_prob + xgb_phish_prob)`.
   - Scales to integer range: `ensemble_score = min(100, max(0, round(avg_prob * 100.0)))`.

---

### 3.b) Config Existence, Code Changes, and Affected Result Files
1. **Does a configuration exist that excludes the ensemble?**  
   - **Production Backend:** **NO**. No flag, environment variable, or configuration toggle exists in `analyze.py` to bypass the ensemble when `models/ensemble_rf.pkl` and `ensemble_xgb.pkl` are present.
   - **Evaluation Runner (`tools/run_round2_evaluations.py`):**  
     - `config="heuristics_only"`: Bypasses ensemble, but runs Layer 1 in isolation (no DistilBERT, no behavioral).
     - `config="heuristics_distilbert"`: Runs heuristics + DistilBERT, but uses dynamic `s_b = evaluate_behavioral(payload)` rather than the neutral baseline ($S_b=15$), and lacks the Config 4 attachment+urgency threat floor (`score >= 52`).
     - **Finding:** No configuration exists for the Full Pipeline with neutral baseline and ensemble excluded.
2. **Exact Code Change Needed to Exclude Ensemble:**  
   In `aegis-backend/routes/analyze.py`, at Line 407:
   ```python
   # Replace:
   if ensemble_used:
       blended = round(0.60 * s_heuristic + 0.40 * s_ensemble)
       s_layer1 = min(100, blended)
   # With:
   if ensemble_used and False: # or: if ensemble_used and not DISABLE_ENSEMBLE:
       blended = round(0.60 * s_heuristic + 0.40 * s_ensemble)
       s_layer1 = min(100, blended)
   ```
3. **Result Files Requiring Re-Running:**  
   - **Main 100-Sample Template Set:**  
     - `evidence/E-08_phishing-corpus-metrics/E-08_phishing-corpus-metrics_predictions_*.csv`
     - `evidence/E-08_phishing-corpus-metrics/E-08_phishing-corpus-metrics_report_*.json`
     - `evidence/E-07_ablation/E-07_ablation_summary_*.csv`
     - `evidence/E-24_threshold-sweep/E-24_threshold_sweep_*.csv`
   - **Public Test Split ($N=50$) & Train Calibration ($N=200$):**  
     - `evidence/E-39_independent-corpus/E-39_predictions_full_standard.csv`
     - `evidence/E-39_independent-corpus/E-39_predictions_heuristics_ensemble_standard.csv`
     - `evidence/E-39_independent-corpus/E-39_round2_master_summary.json`
     - `evidence/E-39_independent-corpus/E-39_train_calibration_report.json`
     - `evidence/E-39_independent-corpus/E-39_calibrated_eval_all_sets.json`
     - `evidence/E-39_independent-corpus/nazario_only_eval.json`
   - **LLM-Authored Set ($N=60$):**  
     - `evidence/E-43_llm-authored-eval/E-43_llm_predictions.csv`
     - `evidence/E-43_llm-authored-eval/E-43_llm_summary.json`
   - **Philippine / Taglish Set ($N=60$):**  
     - `evidence/E-42_philippine-taglish/E-42_philippine_evaluation.csv`
     - `evidence/E-42_philippine-taglish/E-42_philippine_summary.json`
4. **Empirical Read-Only Execution Across All 4 Datasets (With vs Without Ensemble):**  
   We executed an in-memory non-destructive pipeline test monkey-patching `evaluate_layer1` across all 4 datasets with DistilBERT warm:

| Dataset | Metric ($T=45$) | With Ensemble (Production) | Without Ensemble ($S_{\text{layer1}} = S_h$) | Delta |
|---|:---:|:---:|:---:|:---:|
| **Main Template Set ($N=100$)** | Recall / FPR / AUC | 100.0% / 0.0% / 1.000 | 100.0% / 0.0% / 1.000 | 0.0% |
| **Public Test Split ($N=50$)** | Recall / FPR / AUC | 32.0% / 0.0% / 1.000 | 32.0% / 0.0% / 1.000 | 0.0% |
| **Taglish Benchmark ($N=60$)** | Recall / FPR / AUC | 16.67% / 0.0% / 0.7078 | 16.67% / 0.0% / 0.7078 | 0.0% |
| **LLM-Authored Set ($N=60$)** | Recall / FPR / AUC | 3.33% / 0.0% / 0.7611 | 3.33% / 0.0% / 0.7611 | 0.0% |

*(Note: While dropping the ensemble reduces Layer 1 standalone AUC from 0.732 to 0.690 per E-41, full-pipeline metrics at threshold 45 remain identical across all 4 benchmark sets because DistilBERT weights and threat-floor logic dominate composite decision outcomes).*

---

## 4. THRESHOLDS AND PRESETS

### 4.a) Sensitivity Preset Definitions and Usages
1. **Exact Definitions:**  
   `aegis-extension/dashboard/dashboard.js`, Lines 515–519:
   - **Conservative:** Warning $\ge 35$, Critical $\ge 65$
   - **Standard (Default):** Warning $\ge 45$, Critical $\ge 75$ (`DEFAULT_SENSITIVITY`, Line 39)
   - **Aggressive:** Warning $\ge 55$, Critical $\ge 85$
2. **Every Place Used:**  
   - `aegis-extension/dashboard/dashboard.html`, Lines 240–265: Buttons `#preset-conservative`, `#preset-standard`, `#preset-aggressive`.
   - `aegis-extension/dashboard/dashboard.js`, Lines 36, 39, 503–600, 667: UI slider binding, event listeners, local persistence key `aegis_sensitivity`.
   - `tools/run_phase_c_evaluations.py`, Line 463: Threshold sensitivity sweep list `[35, 45, 50, 55, 65, 75, 85]`.
   - **Limitation Finding:** Preset values are stored in `chrome.storage.local` but are **NOT read by `content_script.js` or `local_heuristics.js`**, nor sent to `aegis-backend/routes/analyze.py`. Production scanning runs on hardcoded thresholds (45 Warning, 75 Critical).

---

### 4.b) Evaluation of Critical Cut-Offs (65, 75, 85)
**YES**. Evaluated in `evidence/E-24_threshold-sweep/E-24_threshold-sweep_summary_20261108_0c541f5.csv` and `E-24_threshold-sweep_log_20261108_0c541f5.log` on the main 100-sample test set:

| Critical Cut-Off ($T$) | TP | FP | TN | FN | Recall (%) | FPR (%) | Precision (%) | F1-Score (%) | Accuracy (%) |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **65 (Conservative Crit)** | 34 | 0 | 50 | 16 | **68.0%** | **0.0%** | 100.0% | 80.95% | 84.0% |
| **75 (Standard Crit)** | 1 | 0 | 50 | 49 | **2.0%** | **0.0%** | 100.0% | 3.92% | 51.0% |
| **85 (Aggressive Crit)** | 0 | 0 | 50 | 50 | **0.0%** | **0.0%** | 0.0% | 0.00% | 50.0% |

---

### 4.c) Evaluation of Cut-Offs 20–35 on Main 100-Sample Set
- **Continuous Sweep 20–35 on Main Set:** **NOT FOUND**. No script executes an integer range sweep ($T = 20, 21, \dots, 35$) on `data/test_dataset.csv`.
- **Discrete Points Evaluated:**
  - Cut-off 35: Evaluated in `tools/run_phase_c_evaluations.py:463` and `evidence/E-24_threshold-sweep/` (Recall = 100.0%, FPR = 18.0%, TP = 50, FP = 9).
  - Cut-offs 20 and 25: Evaluated in `tools/evaluate_all_sets_calibrated.py:107–128` (Recall = 100.0%, FPR = 24.0% at $T=20$; Recall = 100.0%, FPR = 22.0% at $T=25$).

---

## 5. PII SCRUBBER COVERAGE

### 5.a) Exact Redaction Patterns in `aegis-extension/pii_scrubber.js` (Lines 51–105)
1. **Email Addresses:**  
   `regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/gi` $\rightarrow$ `[EMAIL]`
2. **Payment Card Numbers (Luhn Checksum Validated):**  
   `regex: /\b(?:\d[ -]*?){13,19}\b/g` $\rightarrow$ `isValidLuhn(digits)` $\rightarrow$ `[CARD_NUMBER]`
3. **US Social Security Number (SSN):**  
   `regex: /\b(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}\b/g` $\rightarrow$ `[SSN]`
4. **Philippine SSS:**  
   `regex: /\b\d{2}-\d{7}-\d{1}\b/g` $\rightarrow$ `[SSN]`
5. **Philippine PhilHealth:**  
   `regex: /\b\d{2}-\d{9}-\d{1}\b/g` $\rightarrow$ `[SSN]`
6. **Philippine TIN (Tax Identification Number):**  
   `regex: /\b\d{3}-\d{3}-\d{3}(-\d{3})?\b/g` $\rightarrow$ `[SSN]`
7. **Telephone Numbers (PH Mobile/Landline + US/E.164):**  
   `regex: /(?:(?:\+?63[\s.-]?|0)9\d{2}[\s.-]?\d{3}[\s.-]?\d{4}\b)|(?:(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\b\d{3})[\s.-]?\d{3}[\s.-]?\d{4}\b)/g` $\rightarrow$ `[PHONE]`
8. **Contextual Salutation Names:**  
   `regex: /\b(Dear|Hi|Hello|Hey|Greetings)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)(?=[,\s\n\r!])/g` $\rightarrow$ `$1 [NAME]`
9. **Contextual Sign-off Names:**  
   `regex: /\b(Sincerely|Regards|Best regards|Warm regards|Thanks|Thank you|Yours truly),?\s*\n+\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b/g` $\rightarrow$ `$1,\n[NAME]`

---

### 5.b) Philippine Government IDs Coverage & Unit Tests
- **TIN (Tax Identification Number):** **HANDLED**. Regex at line 84. Tested in `aegis-extension/tests/test_pii_scrubber.js`, Lines 74–82 (`TIN: 123-456-789-000` $\rightarrow$ `[SSN]`).
- **PhilHealth:** **HANDLED**. Regex at line 79. Tested in `test_pii_scrubber.js`, Lines 74–82 (`PhilHealth: 12-345678901-2` $\rightarrow$ `[SSN]`).
- **SSS (Social Security System):** **HANDLED**. Regex at line 74. Tested in `test_pii_scrubber.js`, Lines 74–82 (`SSS: 02-1234567-9` $\rightarrow$ `[SSN]`).
- **UMID (Unified Multi-Purpose ID):** **NOT FOUND / NO DEDICATED REGEX**. (CRN / 12-digit format `XXXX-XXXXXXX-X` has no rule).
- **PhilSys (National ID / PhilID):** **NOT FOUND / NO DEDICATED REGEX**. (16-digit format `XXXX-XXXX-XXXX-XXXX` has no rule; fails card Luhn validation).

---

## 6. LATENCY REQUEST COUNT

### 6.a) Raw File Citation
- **File Path:** `evidence/E-45_small-fixes/live_render_telemetry_30warm_3cold_20261108_19affee.json`
- **Associated Commit:** `19affee1814c882d8b80390746995777453bc45e`
- **Timestamp:** `2026-11-08T17:47:13.474212+00:00`

---

### 6.b) Request Count Reconciliation (29 vs 30)
- **Total Requests Recorded:** Exactly **30 requests** recorded in the `samples_evaluated` array (Lines 55–298) and logged at line 49 (`"total_warm_requests": 30`).
- **First-Request / Container Initialization:** Sample ID 24 (Sample 1 in array, lines 56–63) recorded a latency of **8,605.5 ms** due to initial FastAPI worker process and ONNX runtime invocation.
- **Steady-State Warm Requests:** The remaining **29 requests** executed in steady state with latencies between **657.7 ms and 1,095.9 ms** (Median: **803.1 ms**, Mean: 827.0 ms, zero violations >2.0s).
- **Cold-Start Trials:** 3 separate spin-up trials from container hibernation were measured: Trial 1 = 52.5 s, Trial 2 = 54.1 s, Trial 3 = 51.9 s (Mean: **52.8 s**).

---

## 7. MULTI-TAB / RESOURCE MEASUREMENT

### 7.a) Profile Source and Empirical Observations
- **Raw File:** `evidences/08_browser_and_ram_evidence.txt` (Committed in `8c42233da6027148ccf0f735d7217b991d18bc3c`, Oct 23, 2026).
- **Methodology:** Manual inspection via **Google Chrome Task Manager (`Shift + Esc`)** and Windows Task Manager on Windows 11 Enterprise (x64):
  - Target Task: `Extension: Aegis: AI-Powered Phishing Context Analyzer`
  - Process ID: `14208`
  - Memory Footprint (RSS): **78.4 MB** (reported as 78 MB in manuscript).
  - CPU Utilization: **0.0% – 3.8%** during active DOM scanning (< 4% peak).

---

### 7.b) Gmail Tabs, Duration, and Chrome Version
- **Number of Gmail Tabs Open:** **NOT FOUND** in `08_browser_and_ram_evidence.txt` (only notes "Active Scanning of Gmail DOM" and an isolated iframe subframe `apis.google.com ~35.1 MB`).
- **Measurement Duration:** **NOT FOUND** in `08_browser_and_ram_evidence.txt` (no start/end timestamps or test duration recorded).
- **Chrome Version:** **Google Chrome Product Version `155.0.8059.85` (Official Build, 64-bit)** (Line 17; line 34 notes `Google Chrome 120+`).
- **Manifest Status of Multi-Tab Memory Tracking:** Marked as **DROPPED / UNVERIFIED** in `evidence/MANIFEST.md`, Line 39:  
  `| E-18 | multitab-memory | N/A (Performance testing script) | DROPPED / UNVERIFIED | Multi-tab memory tracking dropped per faculty re-scoping. |`

---

## 8. COMMIT / TAG RECONCILIATION

### 8.a) `git merge-base --is-ancestor` Verification
Target tag: `v1.0-capstone-submission` (Points to commit `dede10130f9ced052c7f241ac1c5d19e972cc3bb`).

Command executed:
```powershell
git merge-base --is-ancestor <commit> dede101
```

| Commit Hash | Commit Subject & Date | `git merge-base --is-ancestor` Result | Exit Code | Ancestor Status |
|---|---|:---:|:---:|:---:|
| `0c541f5` | `feat(matrix): add Revision Matrix v15 builder...` (2026-11-08) | **True** | 0 | **CONFIRMED ANCESTOR** |
| `95c6d12` | `eval-only: add Phase C Round 2 evaluation suite...` (2026-11-08) | **True** | 0 | **CONFIRMED ANCESTOR** |
| `19affee` | `feat(calibration): calibrate Warning cut-off on 200-email train...` (2026-11-09) | **True** | 0 | **CONFIRMED ANCESTOR** |
| `24be0d0` | `validation: add reviewer comments to evaluation scripts...` (2026-11-08) | **True** | 0 | **CONFIRMED ANCESTOR** |
| `326b02d` | `feat(prototype): complete Week 3.6 feature-complete prototype...` (2026-10-05) | **True** | 0 | **CONFIRMED ANCESTOR** |

**Finding:** All 5 audited commits are strict lineal ancestors of tag `v1.0-capstone-submission` (`dede101`).

---

## 9. TELEMETRY

### 9.a) Data Collected and Storage Locations
1. **Chrome Extension Client Context:**
   - **Data Collected:**
     - `aegis_detection_log`: Ring buffer (up to 100 entries). Fields: `emailHash` (btoa/SHA-256), `score` (0–100), `riskLevel` (`Safe`, `Warning`, `Critical`), `sender`, `subject`, `source` (`local`/`backend`), `analyzedAt` (ISO timestamp), `userOverride` (boolean). (`aegis-extension/overlay/overlay.js:1097–1106`).
     - `aegis_feedback_log`: False-positive user override reports (`emailHash`, `userVerdict`, `reason`, `reportedAt`).
     - `aegis_sender_history`: Interaction frequency and circular timestamps per sender domain (`aegis-extension/content_script.js:514–595`).
   - **Storage Location:** Browser-local `chrome.storage.local`.
2. **Backend Server Context:**
   - **Data Collected:**
     - `_detection_log`: Array of up to 1,000 entries received via `POST /api/v1/log-result`. Fields: `emailHash`, `score`, `riskLevel`, `sender` (scrubbed), `subject` (scrubbed), `source`, `analyzedAt`. (`aegis-backend/routes/analyze.py:831, 877–885`).
     - `_feedback_log`: Array of feedback reports received via `POST /api/v1/feedback`.
     - `_vt_cache`: In-memory dictionary of domain/URL reputation results.
   - **Storage Location:** **Volatile Python process RAM only** (`aegis-backend/routes/analyze.py:831–835`). No SQL/NoSQL database or disk persistence exists (`evidence/E-28_in-memory-dict-check/`).

---

### 9.b) User Opt-Out Status
- **Is there a user opt-out?** **NO**.
- There is **no configuration setting, preference flag, or UI toggle** in the popup, dashboard, or background script to disable telemetry collection or local detection logging. Users may manually clear historical logs via the "Clear Log" button (`dashboard.js:493` or `POST /api/v1/detection-log/clear`), but cannot opt out of ongoing collection.

---

## 10. EVIDENCE INDEX (E-01 to E-45)

We inspected the disk status of every evidence identifier against `evidence/MANIFEST.md` and repository directory contents:

| ID | Canonical Slug | File Path or Formal Status | Disk Verification Result |
|:---:|---|---|:---:|
| **E-01** | `title-approval` | `N/A (Administrative institutional record)` | **NOT FOUND** (DROPPED / UNVERIFIED) |
| **E-02** | `render-region` | `N/A (Institutional cloud console record)` | **NOT FOUND** (DROPPED / UNVERIFIED) |
| **E-03** | `backend-payload` | `evidence/E-03_backend-payload/E-03_backend-payload_refs_20261107_85e8e3a.md` | **EXISTS** |
| **E-04** | `request-body-logging` | `evidence/E-04_request-body-logging/E-04_request-body-logging_refs_20261107_85e8e3a.md` | **EXISTS** |
| **E-05** | `placeholder-benchmark` | `evidence/E-05_placeholder-benchmark/E-05_placeholder-benchmark_20261023_8c42233.json` | **EXISTS** (WITHDRAWN) |
| **E-06** | `full-pipeline-rerun` | `evidence/E-06_full-pipeline-rerun/E-06_full-pipeline-rerun_20261107_160d746.json` | **EXISTS** (WITHDRAWN) |
| **E-07** | `ablation` | `evidence/E-07_ablation/E-07_ablation_summary_20261108_0c541f5.csv` | **EXISTS** |
| **E-08** | `phishing-corpus-metrics` | `evidence/E-08_phishing-corpus-metrics/E-08_phishing-corpus-metrics_report_20261108_0c541f5.json` | **EXISTS** |
| **E-09** | `flower-shop-probe` | `evidence/E-09_flower-shop-probe/E-09_flower-shop-probe_output_20261106_na.json` | **EXISTS** |
| **E-10** | `scoring-formula-code` | `evidence/E-10_scoring-formula-code/E-10_scoring-formula-code_refs_20261107_91e1e8d.md` | **EXISTS** |
| **E-11** | `auth-inference-code` | `evidence/E-11_auth-inference-code/E-11_auth-inference-code_refs_20261107_91e1e8d.md` | **EXISTS** |
| **E-12** | `manuscript-figure-audit` | `evidence/E-12_manuscript-figure-audit/E-12_manuscript-figure-audit_20261107_d801129.txt` | **EXISTS** |
| **E-13** | `two-tier-xai-panel` | `evidence/AUDIT_ROUND2.md (Item 7.b)` (No PNG screenshot file) | **NOT FOUND** (DROPPED / UNVERIFIED) |
| **E-14** | `spf-dkim-drawer-states` | `evidence/E-14_spf-dkim-drawer-states/E-14_spf-dkim-drawer-states_test-output_20261107_799f152.txt` | **EXISTS** |
| **E-15** | `virustotal-reasons-panel` | `evidence/AUDIT_ROUND2.md (Item 2.c)` (No PNG screenshot file) | **NOT FOUND** (DROPPED / UNVERIFIED) |
| **E-16** | `threshold-presets` | `evidence/AUDIT_FOR_MANUSCRIPT.md` (No PNG screenshot file) | **NOT FOUND** (DROPPED / UNVERIFIED) |
| **E-17** | `post-defense-ui-commits` | `evidence/E-17_post-defense-ui-commits/E-17_post-defense-ui-commits_20261107_a824a4e.txt` | **EXISTS** |
| **E-18** | `multitab-memory` | `N/A (Performance testing script)` | **NOT FOUND** (DROPPED / UNVERIFIED) |
| **E-19** | `scan-trigger-ratelimit` | `evidence/E-19_scan-trigger-ratelimit/E-19_scan-trigger-ratelimit_refs_20261107_6a6ba94.md` | **EXISTS** |
| **E-20** | `test-set-composition` | `evidence/E-20_test-set-composition/E-20_test-set-composition_report_20261107_91e1e8d.md` | **EXISTS** |
| **E-21** | `model-provenance` | `evidence/E-21_model-provenance/E-21_model-provenance_20261107_320e9b3.md` | **EXISTS** |
| **E-22** | `taglish-test` | `evidence/E-42_philippine-taglish/E-42_philippine_evaluation.csv` | **SUPERSEDED** (by E-42) |
| **E-23** | `uat-data` | `evidence/E-23_uat-data/E-23_uat-data_report_20261107_0c541f5.md` | **EXISTS** |
| **E-24** | `threshold-sweep` | `evidence/E-24_threshold-sweep/E-24_threshold-sweep_summary_20261108_0c541f5.csv` | **EXISTS** |
| **E-25** | `citation-check` | `evidence/E-25_citation-check/E-25_citation-check_sources_20261107_a482063.md` | **EXISTS** |
| **E-26** | `primary-reports` | `evidence/AUDIT_FOR_MANUSCRIPT.md` (No PDF reports file) | **NOT FOUND** (DROPPED / UNVERIFIED) |
| **E-27** | `gmail-use-confirmation` | `evidence/E-27_gmail-use-confirmation/E-27_gmail-use-confirmation_refs_20261107_a482063.md` | **EXISTS** |
| **E-28** | `in-memory-dict-check` | `evidence/E-28_in-memory-dict-check/E-28_in-memory-dict-check_refs_20261107_85e8e3a.md` | **EXISTS** |
| **E-29** | `fr01-fr08-wording` | `evidence/E-29_fr01-fr08-wording/E-29_fr01-fr08-wording_refs_20261107_a482063.md` | **EXISTS** |
| **E-30** | `revised-page-numbers` | `evidence/AUDIT_FOR_MANUSCRIPT.md` (No dedicated mapping file) | **NOT FOUND** (DROPPED / UNVERIFIED) |
| **E-31** | `repro-package` | `evidence/E-31_repro-package/E-31_repro-package_v2readme_20261108_24be0d0.md` | **EXISTS** |
| **E-32** | `nfr04-sample-size` | `evidence/E-32_nfr04-sample-size/E-32_nfr04-sample-size_v2output_20261107_0c541f5.txt` | **EXISTS** |
| **E-33** | `inter-rater` | `evidence/E-33_inter-rater/E-33_inter-rater_report_20261107_a482063.md` | **EXISTS** |
| **E-34** | `transactional-fpr` | `evidence/E-34_transactional-fpr/E-34_transactional-fpr_report_20261108_0c541f5.txt` | **EXISTS** |
| **E-35** | `ph-brand-test` | `evidence/E-42_philippine-taglish/E-42_philippine_evaluation.csv` | **SUPERSEDED** (by E-42) |
| **E-36** | `string-audit` | `evidence/E-36_string-audit/E-36_string-audit_20261107_fca8158.txt` | **EXISTS** |
| **E-37** | `shortener-unit-tests` | `aegis-backend/tests/test_link_scanner.py` | **EXISTS** (in backend tests) |
| **E-38** | `shortener-test-log` | `evidences/07_unit_tests_run.txt` | **EXISTS** (in evidences/) |
| **E-39** | `independent-corpus` | `evidence/E-39_round2_master_summary.json` | **EXISTS** |
| **E-40** | `layers-3-and-4` | `evidence/E-40_layers-3-and-4/E-40_live_vt_summary.json` | **EXISTS** |
| **E-41** | `ensemble-investigation` | `evidence/E-41_ensemble-investigation/E-41_weight_sensitivity_borderline.csv` | **EXISTS** |
| **E-42** | `philippine-taglish` | `evidence/E-42_philippine-taglish/E-42_philippine_evaluation.csv` | **EXISTS** |
| **E-43** | `llm-authored-eval` | `evidence/E-43_llm-authored-eval/E-43_llm_predictions.csv` | **EXISTS** |
| **E-44** | `explainability-protocol` | `evidence/E-44_explainability-protocol/STUDY_PROTOCOL.md` | **EXISTS** |
| **E-45** | `small-fixes` | `evidence/E-45_small-fixes/live_render_telemetry_30warm_3cold_20261108_19affee.json` | **EXISTS** |

---

## 11. LABELS AND PROVENANCE

### 11.a) Taglish and LLM Set Labels, Authorship, and Second-Annotator Files
1. **Philippine / Taglish Benchmark ($N = 60$):**
   - **Label Definition:** Labels (`1` for phishing, `0` for legitimate) are hardcoded in the dictionary `ph_samples` in `tools/run_round2_evaluations.py`, Lines 1269–1353, and exported to `evidence/E-42_philippine-taglish/E-42_philippine_evaluation.csv`.
   - **Author (Git Blame):** `j4ffyy <jafgrengia@gmail.com>` (Commits `95c6d12` and `11564ab`). Authored manually by the research proponents (`jafgrengia`) as a localized evaluation benchmark; no LLM was used in drafting these emails (`AUDIT_ROUND5.md`, §6.2).
   - **Second-Annotator File:** **NOT FOUND**. No second-annotator scoresheet or inter-annotator agreement log exists for the 60 Taglish emails.
2. **LLM-Authored Set ($N = 60$):**
   - **Label Definition:** Labels are defined in `evidence/E-43_llm-authored-eval/E-43_llm_predictions.csv` (Lines 2–61) and embedded in `tools/run_round2_evaluations.py`, Lines 1414–1540.
   - **Author / Generator:** Prompts executed via `claude.ai` and committed by `j4ffyy <jafgrengia@gmail.com>` in commits `95c6d12` and `11564ab`.
   - **Second-Annotator File:** **NOT FOUND**. No second-annotator file exists.

---

### 11.b) Saved LLM Prompts (E-43), Generation Date, and Model Identifier
Direct citation of `evidence/E-43_llm-authored-eval/E-43_llm_generation_prompts.json` (Lines 1–9):
- **Generator / Model Identifier:** `claude.ai` (Lines 2–3)
- **Generation Date:** `2026-11-08` (Line 4)
- **Evaluation Scope:** "Evaluates defensive resilience against LLM-authored phishing lures without explicit keyword cues" (Line 5)
- **Legitimate Prompt:**
  > `"Generate 30 realistic, diverse corporate and SME office emails: meeting syncs, HR updates, invoices, IT notices, facilities, and project milestones. Tone must be professional and authentic."` (Line 6)
- **Phishing Prompt:**
  > `"Generate 30 defensive phishing detection benchmark templates covering standard enterprise attack archetypes: credential harvesting, fake IT alerts, payroll redirection, DocuSign lures, and executive BEC lures using fictitious domain examples."` (Line 7)
- **Filtering and Refusals:**
  > `"No safety filter refusals occurred because all generated lures adhered strictly to defensive benchmark guidelines (using non-functional fictitious URLs, mock domains, and standard academic evaluation archetypes without weaponized exploits or live phishing infrastructure)."` (Line 8)

---

## 12. AI-TOOL DISCLOSURE FACTS (FOR APPENDIX B)

Strictly derived from git history, repository documents (`AI_USE.md`, `AGENT_LOG.md`), source comments, and configuration files without inference:

1. **`claude.ai` (Commercial Large Language Model Interface):**
   - **Evidence:**  
     - `evidence/E-43_llm-authored-eval/E-43_llm_generation_prompts.json:2–3` (`"generator": "claude.ai"`, `"model_name": "claude.ai"`).
     - `tools/calibrate_warning_cutoff.py:6, 119` (`Generator: claude.ai`, `"generator": "claude.ai"`).
     - Git commit: `ad02e33dcf8e41f5e5c778b7e750026d9276bdc0` (2026-11-09).
   - **Used For:**  
     - Generating the 60 synthetic corporate benchmark emails (30 phishing lures, 30 legitimate emails) in E-43.
     - Structuring and drafting the 200-sample training split warning cut-off calibration script (`tools/calibrate_warning_cutoff.py`).
2. **`Antigravity` (Defensive AI Architecture Audit Agent):**
   - **Evidence:**  
     - `AGENT_LOG.md:3` (`Operator: AI agent (antigravity)`).
     - `AI_USE.md:24` (`Autonomous Evaluation & Auditing Agent (Antigravity)`).
     - `evidence/AUDIT_ROUND2.md`, `AUDIT_ROUND3.md`, `AUDIT_ROUND4.md`, `AUDIT_ROUND5.md` (e.g. `AUDIT_ROUND5.md:4`: `Evaluator: Antigravity`).
   - **Used For:**  
     - Forensic auditing of evaluation harnesses, manifest reconciliation, SHA-256 digest validation, empirical latency capture, and generating audit reports (`AUDIT_ROUND2.md` through `AUDIT_ROUND5.md`, `FINAL_INTEGRITY_REPORT.md`, `FINAL_SUBMISSION_REPORT.md`).
3. **Interactive AI Coding Assistants (Proponent Self-Disclosure):**
   - **Evidence:**  
     - `AI_USE.md:23` (Proponent disclosure).
     - Git commit metadata records human committer `j4ffyy <jafgrengia@gmail.com>`. Specific AI model version and session IDs are designated **UNKNOWN in Git history**.
   - **Used For:**  
     - Drafting architecture specifications in `implementation_plan.md`, Chrome extension DOM/UI handlers (`content_script.js`, `overlay.js`, `pii_scrubber.js`), and backend FastAPI routes (`routes/analyze.py`).
4. **Embedded Machine Learning Model: DistilBERT (`lemonade-sdk/phishing-email-detection-distilbert-ONNX`):**
   - **Evidence:**  
     - `aegis-backend/models/phishing_distilbert/model.onnx` (SHA-256: `361ebc80a1aa7f48778ad007abed802f93fc807ffbd741e8661cf3837c200db0`).
     - `evidence/E-21_model-provenance/E-21_model-provenance_20261107_320e9b3.md:1–52`.
   - **Used For:**  
     - Operational runtime component for Layer 2 natural language semantic phishing classification.
5. **Embedded Machine Learning Model: Scikit-learn Random Forest & XGBoost:**
   - **Evidence:**  
     - `aegis-backend/models/ensemble_rf.pkl` & `aegis-backend/models/ensemble_xgb.pkl`.
     - `aegis-backend/scripts/train_ensemble.py:1–250`.
   - **Used For:**  
     - Operational runtime component for Layer 1 syntactic and structural feature classification.

---

## DISCREPANCIES WITH THE MANUSCRIPT

The following items represent concrete discrepancies between claims or figures in the capstone manuscript and the empirical facts of the repository:

1. **Nazario Test Set Composition:**  
   - *Manuscript Claim:* Suggests an independent evaluation on a "Nazario phishing test set".  
   - *Repository Reality:* `evidence/E-39_independent-corpus/E-39_dataset_test_50.csv` contains only **14 Nazario emails and 11 SpamAssassin generic spam emails** among its 25 positives. The reconstructed pure Nazario set has **9 of its 25 test samples (36.0%) overlapping the training set by body hash**.
2. **Early DistilBERT Evaluation Fallback (E-05, E-06, and Early Calibration):**  
   - *Manuscript Claim:* Reports that Phase 1 and early benchmark accuracy reflected DistilBERT inference.  
   - *Repository Reality:* DistilBERT model weights were **not loaded** during those runs (`load_nlp_model()` was not called). Inference operated purely via `_fallback_classification()` (`base = 20 if len(text) > 100 else 10`). Formally retracted in `evidence/MANIFEST.md` under E-05 and E-06.
3. **Usability Instrument (SUS vs Custom Likert):**  
   - *Manuscript Claim:* References evaluation against the System Usability Scale (SUS, Brooke 1996; 10-item scale).  
   - *Repository Reality:* A 10-item SUS questionnaire was **never administered**. Usability evaluation (`evidence/E-23_uat-data/`) administered a **4-item custom Likert questionnaire** across $N = 6$ participants.
4. **Multi-Tab Memory & Resource Footprint:**  
   - *Manuscript Claim:* Reports "78 MB RSS under multi-tab Gmail load".  
   - *Repository Reality:* The raw log (`evidences/08_browser_and_ram_evidence.txt`) records a single measurement (**78.4 MB**) on one process (PID 14208) using Chrome Task Manager. **The number of open Gmail tabs and measurement duration are unrecorded**. Multi-tab test item E-18 was formally dropped per faculty re-scoping.
5. **Phase C Latency Scope (In-Process vs Live Cloud API):**  
   - *Manuscript Claim:* Cites "91.93 ms average latency" as system processing speed.  
   - *Repository Reality:* The 91.93 ms figure measures **local in-process Python CPU execution time** without network transit (`tools/run_phase_c_evaluations.py`). Live round-trip requests to the Render.com cloud service (`evidence/E-45_small-fixes/`) have a **median latency of 803.1 ms** (warm) and a **mean cold-start delay of 52.8 seconds**.
6. **Sensitivity Preset Dynamism:**  
   - *Manuscript Claim:* Describes adjustable sensitivity presets (Conservative 35/65, Standard 45/75, Aggressive 55/85) for user risk tuning.  
   - *Repository Reality:* Preset thresholds are saved to `chrome.storage.local` in the dashboard UI, but **are never consumed by `content_script.js`, `local_heuristics.js`, or the backend `analyze.py`**. Runtime scanning strictly executes hardcoded 45/75 thresholds.
7. **Missing Evidence Screenshots & Files:**  
   - *Manuscript / Preliminary Ledger:* References evidence files E-01 (Title approval), E-02 (Render region screenshot), E-13 (Two-tier XAI screenshot), E-15 (VirusTotal reasons screenshot), E-16 (Threshold presets screenshot), E-18 (Multi-tab memory log), E-26 (CICC/Check Point reports), and E-30 (Page mapping).  
   - *Repository Reality:* None of these exist as standalone image or document files in the repository. All are formally designated in `evidence/MANIFEST.md` as **DROPPED / UNVERIFIED**.
8. **Retracted DMARC and Gmail API Claims:**  
   - *Manuscript Drafts:* Cites DMARC policy enforcement and Gmail API integration.  
   - *Repository Reality:* The extension operates strictly via DOM inspection (`MutationObserver`) in Gmail webmail; no Gmail API scopes are requested in `manifest.json`. DMARC evaluation is not implemented (SPF and DKIM only). Both claims were formally retracted in `evidence/E-25_citation-check/` and `evidence/E-36_string-audit/`.

