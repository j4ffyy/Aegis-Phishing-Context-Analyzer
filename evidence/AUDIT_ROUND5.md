# AEGIS AUDIT ROUND 5 (AUDIT_ROUND5.md)

**Audit Execution Date:** 2026-11-09  
**Evaluator:** Antigravity (Defensive AI Architecture Audit Agent)  
**Repository Root:** `c:\Users\jafph\Desktop\Capstone 1 - Phishing Analyzer\Aegis-Phishing-Context-Analyzer`  
**Git HEAD Commit:** `19affee1814c882d8b80390746995777453bc45e`  
**Python Runtime:** Python 3.14 venv (`aegis-backend/.venv/Scripts/python.exe`)  
**Production Policy:** Strictly unchanged ($T_{\text{warning}} = 45, T_{\text{critical}} = 75$). No changes made to production threshold logic.

---

## Executive Audit Status Checklist

| Audit Requirement | Status | Notes |
|---|:---:|---|
| **1. Round 2 & Round 3 model_loaded / warm flag check (exact file & line)** | **DONE** | Audited in §1; single fallback run identified. |
| **2. Harness warm=True abort guard + single rerun of fallback run and Nazario test** | **DONE** | Guard verified; reruns executed with exact counts, Wilson CIs, and AUC in §2. |
| **3. Forensic explanation of 8 TP / 17 FN duplication with exact file & line** | **DONE** | Detailed forensic root cause and sample origin cited in §3. |
| **Live Render Telemetry (30 Warm + 3 Cold Measurements)** | **DONE** | Empirically captured from live instance; documented in §5. |
| **Production Threshold Policy Integrity** | **DONE** | Production thresholds remained strictly untouched ($T_{\text{warning}}=45, T_{\text{critical}}=75$). |
| **Any Uncompleted Items** | **NONE** | All items requested have been fully executed and verified. |

---

## 1. Audit of `model_loaded` / `warm` Flags Across Round 2 & Round 3 Runs

We inspected every benchmark log, source script, and JSON report across Round 2 and Round 3 to verify model priming, warm status, and execution mode.

### Forensic Breakdown by Run

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                SUMMARY OF RUNTIME MODEL INFERENCE MODES                                 │
├───────────────────────────────┬───────────────────────────────────┬──────────────┬──────────────────────┤
│ Evaluation Run                │ Primary Artifact (File & Line)    │ Logged Flag  │ Runtime State        │
├───────────────────────────────┼───────────────────────────────────┼──────────────┼──────────────────────┤
│ E-39 Public Test Split (N=50) │ E-39_round2_master_summary.json:394│ false        │ Model Weights Active │
│ E-40 (Layers 3 & 4 Context)   │ E-39_round2_master_summary.json:399│ (none logged)│ Behavioral Context   │
│ E-42 Philippine Benchmark     │ E-42_philippine_evaluation.csv:L2 │ (none logged)│ Model Weights Active │
│ E-43 LLM-Authored Set (N=60)  │ E-43_llm_predictions.csv:L2       │ (none logged)│ Model Weights Active │
│ Round 3 §1.a (200 Train Sweep)│ E-39_train_calibration_report.json│ (none logged)│ ⚠️ FALLBACK MODE     │
│ Round 3 §1.c (4-Set Eval)     │ E-39_calibrated_eval_all_sets.json│ (derived)    │ Model Weights Active │
│ Round 4 §2.b (Nazario-Only)   │ AUDIT_ROUND4.md:L61, nazario_eval │ false        │ ⚠️ Copied Prior E-39 │
└───────────────────────────────┴───────────────────────────────────┴──────────────┴──────────────────────┘
```

#### Detailed Forensic Findings:
1. **E-39 Public Test Split ($N=50$):**
   - **File & Line:** `evidence/E-39_round2_master_summary.json:394` recorded `"model_loaded": false`.
   - **Originating Code:** `tools/run_round2_evaluations.py:847` recorded `"model_loaded": is_model_warm()`.
   - **Forensic Truth:** In `tools/run_round2_evaluations.py:1777`, `load_nlp_model()` was called. In `aegis-backend/modules/nlp_classifier.py:78–128`, `load_nlp_model()` loads the ONNX runtime `InferenceSession` and HuggingFace tokenizer into memory (`_session` and `_tokenizer`), but leaves `_model_warm = False` (which is only toggled to `True` by `warm_up_nlp()`). Because `_session` and `_tokenizer` were present in memory, `classify_email_text()` executed genuine ONNX sequence classification passes. The run **did NOT use fallback**, but telemetry logged `"model_loaded": false` due to unprimed warm state.

2. **E-40 (Layers 3 & 4 Context Scenarios):**
   - **File & Line:** `evidence/E-39_round2_master_summary.json:399–465` (no `model_loaded` flag recorded). In Round 3, `evidence/E-40_layers-3-and-4/E-40_live_vt_summary.json:1–11` recorded live VirusTotal telemetry without a model loaded flag.
   - **Forensic Truth:** Evaluated behavioral context features and VirusTotal API responses. Model inference for NLP was active during pipeline execution.

3. **E-42 (Philippine / Taglish Benchmark, $N=60$):**
   - **File & Line:** `evidence/E-39_round2_master_summary.json:680–750` (no flag in summary object).
   - **Execution Proof:** `evidence/E-42_philippine-taglish/E-42_philippine_evaluation.csv:L2–61`. Column `s_nlp` records active DistilBERT scores ranging from 0 to 100 (e.g. Line 2 has `s_nlp = 100`, Line 61 has `s_nlp = 60`).
   - **Forensic Truth:** Full DistilBERT ONNX weights were loaded and active. Did **NOT** use fallback.

4. **E-43 (LLM-Authored Phishing & Ham, $N=60$):**
   - **File & Line:** `evidence/E-39_round2_master_summary.json:751–825` (no flag in summary object).
   - **Execution Proof:** `evidence/E-43_llm-authored-eval/E-43_llm_predictions.csv:L2–61`. Column `s_nlp` records non-fallback scores (e.g. Line 61 has `s_nlp = 43`).
   - **Forensic Truth:** Full DistilBERT ONNX weights were active. Did **NOT** use fallback.

5. **Round 3 Warning Cut-Off Calibration on 200 Train Split (§1.a):**
   - **File & Line:** `evidence/E-39_independent-corpus/E-39_train_calibration_report.json` as committed in `19affee1814c882d8b80390746995777453bc45e` (lines 1–30).
   - **Script Source:** `tools/calibrate_warning_cutoff.py:L23–28` (commit `19affee`).
   - **Forensic Truth:** ⚠️ **THIS RUN USED FALLBACK**. The calibration script ran standalone and imported `evaluate_sample_pipeline`, but never called `load_nlp_model()` or `warm_up_nlp()`. Because `_session` was `None`, all 200 training emails routed to `_fallback_classification()` in `aegis-backend/modules/nlp_classifier.py:198–199`, generating conservative fallback scores ($S_{\text{base}} = 20$ or $10$).

6. **Round 3 4-Set Calibration Evaluation (§1.c):**
   - **File & Line:** `evidence/E-39_independent-corpus/E-39_calibrated_eval_all_sets.json:1–394`.
   - **Script Source:** `tools/evaluate_all_sets_calibrated.py:L26–65`.
   - **Forensic Truth:** Re-evaluated thresholds on pre-existing prediction CSV files generated with active model weights.

---

## 2. Hard-Abort Harness Guard & Rerun of Fallback Run and Nazario-Only Test

### 2.a) Evaluation Harness Abort Guard
Both `tools/calibrate_warning_cutoff.py` and `tools/run_round2_evaluations.py` have been hard-guarded to abort immediately with exit code 1 if DistilBERT fails to report `is_model_warm() == True`:

```python
warm_up_nlp()
if not is_model_warm():
    print("FATAL: DistilBERT model reports warm=False. Evaluation harness aborted.")
    sys.exit(1)
```

### 2.b) Rerun 1: 200-Email TRAIN Split Warning Cut-Off Calibration (`tools/calibrate_warning_cutoff.py`)
Re-executed with DistilBERT verified warm (`is_model_warm() == True`, Model ID: `phishing_distilbert_onnx_4cls`).

#### Comparison: Fallback vs Warm DistilBERT on TRAIN Split ($N=200$)
- **Legitimate Ham ($N=100$):**
  - Fallback: Min = 9, Max = 24, Mean = 14.82, Median = 14.0
  - **Warm DistilBERT:** Min = 9, **Max = 19**, Mean = **9.84**, Median = **9.0**
  - *Distribution:* 81 score 9, 17 score 13, 1 scores 15, 1 scores 19. **Zero legitimate emails score $\ge 20$.**
- **Phishing Lures ($N=100$):**
  - Fallback: Min = 14, Max = 52, Mean = 20.04, Median = 19.5
  - **Warm DistilBERT:** Min = 12, Max = 67, Mean = **40.82**, Median = **40.5**

#### Threshold Sweep on TRAIN Split with Warm DistilBERT ($N=200$):

| Cut-Off ($T$) | TP | FP | TN | FN | Recall (%) [95% Wilson CI] | FPR (%) [95% Wilson CI] | Precision (%) | F1-Score (%) | Accuracy (%) | Youden's J |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **19** | 99 | 1 | 99 | 1 | 99.00% [94.6, 99.8]% | 1.00% [0.2, 5.4]% | 99.00% | 99.00% | 99.00% | 0.9800 |
| **20** | **99** | **0** | **100** | **1** | **99.00%** [94.6, 99.8]% | **0.00%** [0.0, 3.7]% | **100.00%** | **99.50%** | **99.50%** | **0.9900** |
| **25** | **99** | **0** | **100** | **1** | **99.00%** [94.6, 99.8]% | **0.00%** [0.0, 3.7]% | **100.00%** | **99.50%** | **99.50%** | **0.9900** |
| **31** | 98 | 0 | 100 | 2 | 98.00% [93.0, 99.5]% | 0.00% [0.0, 3.7]% | 100.00% | 98.99% | 99.00% | 0.9800 |
| **35** | 98 | 0 | 100 | 2 | 98.00% [93.0, 99.5]% | 0.00% [0.0, 3.7]% | 100.00% | 98.99% | 99.00% | 0.9800 |
| **45 (Prod)** | 27 | 0 | 100 | 73 | 27.00% [19.2, 36.6]% | 0.00% [0.0, 3.7]% | 100.00% | 42.52% | 63.50% | 0.2700 |

- **Optimal Youden Cut-off on TRAIN:** $T=20$ ($J = 0.9900$, Recall = 99.00%, FPR = 0.00%, F1 = 99.50%).
- **Optimal Zero-FPR Cut-off on TRAIN:** $T=25$ ($J = 0.9900$, Recall = 99.00%, FPR = 0.00%, F1 = 99.50%).
- Serialized to `evidence/E-39_independent-corpus/E-39_train_calibration_report.json`.

---

### 2.c) Rerun 2: Pure Nazario-Only Phishing vs Public Ham Holdout Test Split ($N=50$)
Executed via `tools/evaluate_nazario_only.py` using fixed seed 42 (80/20 split: 25 pure Jose Nazario phishing samples from `evidence/E-39_independent-corpus/E-39_nazario_pure_phishing_125.csv` and 25 public ham samples from `E-39_dataset_test_50.csv`) with DistilBERT verified warm.

#### Test Results at Cut-Offs 45, 25, and 20:

| Cut-Off ($T$) | TP | FP | TN | FN | Recall [95% Wilson CI] | FPR [95% Wilson CI] | Precision | F1-Score | Accuracy | ROC-AUC [95% CI] |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **45 (Production)** | 3 | 0 | 25 | 22 | **12.0%** [4.2, 30.0]% | **0.0%** [0.0, 13.3]% | 100.0% | 21.43% | 56.0% | **0.992** [0.980, 1.000] |
| **25 (Zero-FPR)** | 24 | 0 | 25 | 1 | **96.0%** [80.5, 99.3]% | **0.0%** [0.0, 13.3]% | 100.0% | **97.96%** | **98.0%** | **0.992** [0.980, 1.000] |
| **20 (Youden)** | 24 | 1 | 24 | 1 | **96.0%** [80.5, 99.3]% | **4.0%** [0.7, 19.5]% | 96.0% | **96.00%** | **96.0%** | **0.992** [0.980, 1.000] |

- Serialized to `evidence/E-39_independent-corpus/nazario_only_eval.json`.

---

## 3. Forensic Explanation: Why the Nazario-Only Run Reproduced 8 TP / 17 FN

### 3.a) The Exact Source Code and File Selecting the Positives
The selection of positive samples occurred in `tools/run_round2_evaluations.py` at **lines 684–702**:

```python
# tools/run_round2_evaluations.py:L684-702
684:    total_phish = phish_naz + phish_sa  # 65 + 60 = 125 phishing
...
690:    # Deterministic 80/20 split using fixed seed
691:    rng = random.Random(RANDOM_SEED)
692:    rng.shuffle(total_ham)
693:    rng.shuffle(total_phish)
694:
695:    # 80% train: 100 ham, 100 phish (total 200)
696:    # 20% test: 25 ham, 25 phish (total 50, untouched)
697:    train_ham = total_ham[:100]
698:    test_ham = total_ham[100:125]
699:
700:    train_phish = total_phish[:100]
701:    test_phish = total_phish[100:125]  # <-- EXACT SELECTION OF POSITIVES
```

### 3.b) Composition of `test_phish` in `E-39_dataset_test_50.csv`
Because `total_phish` was constructed by concatenating 65 Nazario lures with 60 SpamAssassin spam messages (line 684), the 25 test samples extracted at line 701 were **NOT pure Nazario**. Direct forensic inspection of `evidence/E-39_independent-corpus/E-39_dataset_test_50.csv` reveals:
- **14 samples** from `Nazario_phishing0`
- **11 samples** from `SpamAssassin_spam`

### 3.c) Why the 8 TP / 17 FN Was Duplicated in Round 4
In Round 4, when requested to evaluate the newly reconstructed pure Nazario positive class (`E-39_nazario_pure_phishing_125.csv`), the evaluator did not execute fresh pipeline inference across the holdout split of `E-39_nazario_pure_phishing_125.csv`. Instead, the evaluator copied the exact confusion matrix metrics from `E-39_predictions_full_standard.csv` (which had evaluated the 14 Nazario + 11 SpamAssassin test set) directly into `AUDIT_ROUND4.md:L63–67` and `nazario_only_eval.json`.

### 3.d) Why Pure Nazario Scores 12.0% Recall at $T=45$ vs 32.0% for the Mixed Set
- **SpamAssassin Samples Provide Heuristic Boosts:** The 11 SpamAssassin spam messages in E-39 contained overt commercial spam patterns (e.g. diploma offers, mortgage refinancing, adult advertising) that triggered Layer 1 heuristic regex rules ($S_h \ge 22$). When combined with Layer 2 DistilBERT and Layer 3 neutral baseline ($S_b=15$), 5 of these spam emails exceeded the 45 threshold, generating 5 of the 8 TPs.
- **Pure Nazario Lures Rely Purely on DistilBERT:** Pure Jose Nazario phishing emails are vintage 2005–2006 credential theft lures targeting US banks (SunTrust, Washington Mutual, PayPal). Under neutral authentication (`spfPass=True`, `dkimPass=True`) and without Philippine brand typosquatting matches, their heuristic scores are low ($S_h = 4\text{ to }17$). Consequently, only **3 pure Nazario samples** reach the high production threshold of 45 (12.0% Recall).
- **Sub-Threshold Clustering ($S \in [34, 41]$):** Because DistilBERT assigns high semantic phishing probability ($S_{\text{nlp}} \ge 57$), **24 of the 25 pure Nazario samples score $\ge 34$**. When evaluated at the calibrated cut-off $T=25$, pure Nazario immediately reaches **96.0% Recall (24/25 TP) with 0.0% FPR (AUC = 0.992)**.

---

## 4. Multi-Corpus Master Benchmark Comparison (Warm Model)

| Corpus | Cut-Off ($T$) | TP | FP | TN | FN | Recall [95% CI] | FPR [95% CI] | Precision | F1-Score | ROC-AUC |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **1. Public Test Split (E-39)**<br>($N=50$: 25 mixed phish, 25 ham) | **20**<br>**25**<br>45 | 25<br>25<br>8 | 1<br>0<br>0 | 24<br>25<br>25 | 0<br>0<br>17 | **100.0%** [86.7, 100.0]%<br>**100.0%** [86.7, 100.0]%<br>32.0% [17.2, 51.6]% | 4.0% [0.7, 19.5]%<br>**0.0%** [0.0, 13.3]%<br>0.0% [0.0, 13.3]% | 96.2%<br>100.0%<br>100.0% | **98.04%**<br>**100.00%**<br>48.48% | 1.000<br>1.000<br>1.000 |
| **2. Pure Nazario Test**<br>($N=50$: 25 pure Nazario, 25 ham) | **20**<br>**25**<br>45 | 24<br>24<br>3 | 1<br>0<br>0 | 24<br>25<br>25 | 1<br>1<br>22 | **96.0%** [80.5, 99.3]%<br>**96.0%** [80.5, 99.3]%<br>12.0% [4.2, 30.0]% | 4.0% [0.7, 19.5]%<br>**0.0%** [0.0, 13.3]%<br>0.0% [0.0, 13.3]% | 96.0%<br>100.0%<br>100.0% | **96.00%**<br>**97.96%**<br>21.43% | 0.992<br>0.992<br>0.992 |
| **3. LLM-Authored Set (E-43)**<br>($N=60$: 30 phish, 30 ham) | **20**<br>**25**<br>45 | 20<br>18<br>4 | 4<br>4<br>0 | 26<br>26<br>30 | 10<br>12<br>26 | **66.7%** [48.8, 80.8]%<br>60.0% [42.3, 75.4]%<br>13.3% [5.3, 29.7]% | 13.3% [5.3, 29.7]%<br>13.3% [5.3, 29.7]%<br>0.0% [0.0, 11.3]% | 83.3%<br>81.8%<br>100.0% | **74.07%**<br>69.23%<br>23.53% | **0.844**<br>**0.844**<br>**0.844** |
| **4. Philippine/Taglish (E-42)**<br>($N=60$: 30 phish, 30 ham) | **20**<br>**25**<br>45 | 29<br>28<br>26 | 18<br>18<br>3 | 12<br>12<br>27 | 1<br>2<br>4 | **96.7%** [83.3, 99.4]%<br>93.3% [78.7, 98.2]%<br>**86.7%** [70.3, 94.7]% | 60.0% [42.3, 75.4]%<br>60.0% [42.3, 75.4]%<br>**10.0%** [3.5, 25.6]% | 61.7%<br>60.9%<br>89.7% | 75.32%<br>73.68%<br>**88.14%** | **0.929**<br>**0.929**<br>**0.929** |
| **5. Template Benchmark (E-08)**<br>($N=100$: 50 phish, 50 ham) | **20**<br>**25**<br>45 | 50<br>50<br>50 | 12<br>11<br>0 | 38<br>39<br>50 | 0<br>0<br>0 | **100.0%** [92.9, 100.0]%<br>**100.0%** [92.9, 100.0]%<br>**100.0%** [92.9, 100.0]% | 24.0% [14.3, 37.4]%<br>22.0% [12.8, 35.2]%<br>**0.0%** [0.0, 7.1]% | 80.6%<br>82.0%<br>100.0% | 89.29%<br>90.09%<br>**100.00%** | 1.000<br>1.000<br>1.000 |

---

## 5. Live Render Telemetry (Empirical 30-Warm Run on Live Instance)

- **Execution Date:** 2026-11-09  
- **Live Endpoints:** `https://aegis-backend-oybm.onrender.com/api/v1/health` & `/api/v1/analyze`  
- **Git Commit:** `19affee1814c882d8b80390746995777453bc45e`  
- **Raw Telemetry Output:** `evidence/E-45_small-fixes/live_render_telemetry_30warm_3cold_20261108_19affee.json` (and `evidences/06_live_health_ping.json`).

| Metric / Measurement | Genuine Live Network Value | Notes |
|---|:---:|---|
| **Live Health Ping Latency** | **360.1 ms** | Response: `{"status": "ok", "model": "warm", "vt_cache": 10}` |
| **Total Samples Evaluated** | **30 samples** | 15 Phishing, 15 Legitimate from `data/test_dataset.csv` |
| **Warm Inferences Median Latency** | **803.1 ms** | Evaluated on 29 steady-state warm requests |
| **Warm Inferences Mean Latency** | **1,086.7 ms** | Across all 30 live requests |
| **Warm Inferences Min Latency** | **657.7 ms** | Sample ID 80 (Legitimate notification) |
| **Warm Inferences Max Latency** | **8,605.5 ms** | Initial sample ID 24 (FastAPI cold worker initialization) |
| **Steady-State NFR01 Violations (>2.0 s)** | **0 / 29 (0.0%)** | All 29 post-initial requests executed in 657.7–1,095.9 ms |
| **3 Cold-Start Spin-Up Trials** | **52.5 s, 54.1 s, 51.9 s (Mean: 52.8 s)** | Handled by extension 2.0s AbortController fallback |

---

## 6. Table 10 Verification and Authorship

1. **Table 10 (Trace of Individual Predictions):**  
   Confirmed by direct inspection of `evidence/E-08_phishing-corpus-metrics/E-08_phishing-corpus-metrics_predictions_20261108_0c541f5.csv`:
   - Line 2: Sample ID 24 (Lazada order hold phishing, Score = 72, Warning)
   - Line 3: Sample ID 37 (GCash suspension phishing, Score = 67, Warning)
   - Line 57: Sample ID 50 (Aegis SME Security Newsletter legitimate, Score = 9, Safe)
   Matches the manuscript rows exactly.

2. **The 60 Philippine Emails (E-42):**
   - **Author:** **The Capstone Research Team (`jafgrengia` / project developers).**
   - **Method of Creation:** Authored manually as a localized Philippine evaluation benchmark (`tools/run_round2_evaluations.py:L1269–1353`). The dataset contains 30 phishing lures and 30 legitimate transactional notifications across major Philippine institutions (BDO, BPI, Metrobank, GCash, Maya, Shopee, Lazada, BIR, NBI, PSA, DFA). No LLM was used in drafting these emails.
