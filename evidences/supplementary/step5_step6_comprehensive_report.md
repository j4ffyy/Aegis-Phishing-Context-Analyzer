# AEGIS Supplementary Evaluation: Steps 5 & 6 Report

- **Evaluated Git Commit Hash:** `8c42233da6027148ccf0f735d7217b991d18bc3c`
- **Execution Timestamp:** 2026-10-25 00:01:03 (Updated with Rigorous Forensic Audit)

---

## 1. Step 5a: Trivial Rule-Based Baselines

Evaluated on all 100 benchmark samples (50 phishing / 50 legitimate):

| Baseline Rule | Accuracy (%) [95% CI] | Recall (%) [95% CI] | FPR (%) [95% CI] | Precision (%) | F1-Score (%) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Sender TLD not in {ph, com}** | 98.00% [93.0%, 99.4%] | 96.00% [86.5%, 98.9%] | 0.00% [0.0%, 7.1%] | 100.00% | 97.96% |
| **Link Present Only** | 79.00% [70.0%, 85.8%] | 100.00% [92.9%, 100.0%] | 42.00% [29.4%, 55.8%] | 70.42% | 82.64% |
| **Attachment Present Only** | 74.00% [64.6%, 81.6%] | 48.00% [34.8%, 61.5%] | 0.00% [0.0%, 7.1%] | 100.00% | 64.86% |
| **Sender TLD not in {ph, com} OR Attachment Present** | 100.00% [96.3%, 100.0%] | 100.00% [92.9%, 100.0%] | 0.00% [0.0%, 7.1%] | 100.00% | 100.00% |

---

## 2. Step 5b: Deduplication on (subject, bodyText)

- **Unique Phishing Rows:** 44 (out of 50; 6 duplicate pairs removed)
- **Unique Legitimate Rows:** 45 (out of 50; 5 duplicate pairs removed)
- **Total Unique Corpus:** 89 samples

| Configuration | Accuracy (%) [95% CI] | Recall (%) [95% CI] | FPR (%) [95% CI] | Precision (%) | F1-Score (%) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Full Pipeline (Model Loaded)** | 100.00% [95.9%, 100.0%] | 100.00% [92.0%, 100.0%] | 0.00% [0.0%, 7.9%] | 100.00% | 100.00% |
| **Heuristics-Only (ensemble off)** | 92.13% [84.6%, 96.1%] | 84.09% [70.6%, 92.1%] | 0.00% [0.0%, 7.9%] | 100.00% | 91.36% |
| **DistilBERT-Pure (S_base only)** | 88.76% [80.5%, 93.8%] | 100.00% [92.0%, 100.0%] | 22.22% [12.5%, 36.3%] | 81.48% | 89.80% |

---

## 3. Step 5c: 10 Legitimate Rows Flagged by DistilBERT-Pure

When evaluated in complete isolation without multi-layer heuristics, DistilBERT-pure flagged 10 legitimate samples (FPR: 20.00%):

| ID | Sender | Subject | P_phish | S_heur | S_nlp | Composite | Common Pattern |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 51 | `sss@sss.gov.ph` | Your monthly Lazada invoice is ready | 0.9986 | 4 | 60 | 36 | Invoice / Statement notification keywords |
| 57 | `projectlead@consultancy.ph` | Your monthly Lazada invoice is ready | 1.0000 | 4 | 60 | 36 | Invoice / Statement notification keywords |
| 65 | `contributions@philhealth.gov.ph` | Your PhilHealth contribution receipt for October 2026 | 0.8053 | 4 | 48 | 29 | Invoice / Statement notification keywords |
| 54 | `finance@legitcorp.com.ph` | FWD: MMDC academic calendar update | 0.9996 | 4 | 60 | 36 | Transactional / Billing receipt context |
| 84 | `hr@mmdc.edu.ph` | Shopee Order Confirmation - Order #SHP-2026-12345 | 0.9958 | 4 | 60 | 36 | Transactional / Billing receipt context |
| 85 | `hr@mmdc.edu.ph` | Welcome to the Aegis SME Security Newsletter | 0.9995 | 4 | 60 | 36 | Transactional / Billing receipt context |
| 76 | `mreyes@businesspartner.com.ph` | Follow-up: Contract renewal discussion | 0.9992 | 4 | 60 | 36 | Transactional / Billing receipt context |
| 79 | `jdelacruz@company.com.ph` | Team lunch - please confirm attendance | 0.9679 | 4 | 58 | 35 | Calendar / RSVP notification keywords |
| 52 | `gcash@gcash.com` | Your monthly Lazada invoice is ready | 0.9999 | 4 | 60 | 36 | Invoice / Statement notification keywords |
| 69 | `mreyes@businesspartner.com.ph` | Your monthly Lazada invoice is ready | 1.0000 | 4 | 60 | 36 | Invoice / Statement notification keywords |

**Observation on False Positive Suppression:**
Every single one of these 10 samples has `s_heuristic = 4` or `0` and benign behavioral baseline (`15`). In the composite meta-classifier, the resulting synthesized scores were strictly between `29` and `36`—well below the threshold of `45`—reducing the final False Positive Rate to exactly **0.00%**.

---

## 4. Step 5d: Counterfactual Stress Test

- **Synthetic Perturbation:** (i) All 50 legitimate rows had their sender domain TLD forced to `.xyz`. (ii) All 50 phishing rows had their sender domain TLD forced to `.ph`.
- **Protocol Warning:** This is an in-memory stress test to test feature dominance, not empirical real-world distribution.

- **Observed Accuracy:** **97.00%** [95% CI: 91.5%, 99.0%]
- **Observed Recall:** **100.00%** [95% CI: 92.9%, 100.0%]
- **Observed FPR:** **6.00%** [95% CI: 2.1%, 16.2%] (TP=50, TN=47, FP=3, FN=0)

---

## 5. Step 6: Forensic Audit of Inconsistencies and Historical Mismatches

### A. Layer Claims in `evidences/README.md` vs. Actual Execution
1. **DistilBERT Status:** `evidences/README.md` lines 19 and 46 state that offline evaluation was run through *'Layer 2 (Active): Pre-trained DistilBERT ONNX checkpoint (`lemonade-sdk/phishing-email-detection-distilbert-ONNX`)'*. In reality, `evaluate_models.py` never called `load_nlp_model()` or `warm_up_nlp()`, so ONNX inference never executed during the submitted benchmark run. It operated entirely via `_fallback_classification()` (`base = 20 if len(text) > 100 else 10`).
2. **Layer 1 Blending:** The README describes Layer 1 as *'Heuristic rules + Typosquatting + Tabular Ensemble (RF + XGBoost)'*. The code indeed blended heuristics (60%) and ensemble (40%), but because the tabular ensemble was trained on synthetic features including SPF failure, it produced conservative probabilities under neutral auth that actually reduced recall from 84.00% to 58.00%.

### B. Commit Hash Discrepancies (`c766732` vs. `74fc9af` vs. `89e4948` vs. `8c42233`)
1. **The Inaccuracy in the Paper:**
   - The paper draft claims the benchmark evaluation was run on commit `c766732` (*Oct 22 at 17:50*). This is strictly inaccurate.
   - Commit `c766732` was only the Render deployment URL configuration.
2. **The Actual Git History:**
   - The evaluation harness itself (`evaluate_models.py`) was not committed until **`74fc9af` on Oct 22 at 23:47:03 +0800** (`Feat/w8 8 model evaluation metrics (#23)`).
   - The formal benchmark run was executed the next morning, committed under **`89e4948` on Oct 23 at 11:59:11 +0800**.
   - Thirty-four minutes later, **`8c42233` on Oct 23 at 12:33:49 +0800** committed the neutral-auth sensitivity control and live API telemetry.
3. **Forensic Conclusion:** The paper's claim that the benchmark was executed on `c766732` is factually untrue. The evaluation harness landed 6 hours later at 23:47 (`74fc9af`), and the benchmark results were generated on October 23 (`89e4948` / `8c42233`).

### C. Latency Discrepancy: Ambiguity of the 50.8 ms Figure and Cold-Start Realities
1. **The 50.8 ms Metric Excluded DistilBERT:**
   - Chapter IV Table 17 reports a median latency of **50.8 ms** labeled as "offline."
   - This figure measures the **unloaded heuristic fallback path** inside a local Python loop. Because `evaluate_models.py` never loaded the ONNX model, it executed simple string length checks.
   - When the actual DistilBERT ONNX model is loaded and executed, the real local pipeline latency is **~126.4 ms to 127.0 ms** (median recorded in `evidences/supplementary/step3_step4_summary_table.md`). The 50.8 ms figure significantly understates real full-pipeline execution time.
2. **Discrepancy Between Reports (50.8 ms vs. 68.0 ms):**
   - `evidences/03_evaluation_report.txt` records **50.8 ms median** (65.0 ms mean).
   - `evidences/evaluation_report.txt` records **68.0 ms median** (91.9 ms mean).
   - These represent **separate runs** executed on the workstation; the exact cause of the difference was not recorded.
3. **The 52.5-Second Cloud Cold-Start Reality:**
   - On the Render free-tier, instances spin down after 15 minutes of inactivity. When cold, the first request takes ~52.5 seconds (`06_live_health_ping.json`).
   - The Chrome extension implements a **2-second network timeout followed by a fallback to local heuristics** (`CONFIG.NETWORK_TIMEOUT_MS = 2000`).
   - Any cold-start request aborts after 2 seconds and drops into local heuristic mode. Therefore, NFR01 (< 2.0s response) holds for the cloud pipeline **only when the backend is warm** (median 896.6 ms).
