# Aegis Phishing Analyzer — Reproduction Guide (REPRODUCE.md)

**Target Milestone:** Capstone 1 & 2 Final Submission Benchmark Replication  
**Repository:** `Aegis-Phishing-Context-Analyzer`  
**Git HEAD Reference:** `19affee1814c882d8b80390746995777453bc45e`  
**Execution Timestamp:** 2026-11-09  

---

## 1. System Requirements & Runtime Environment

### 1.1 Operating System & Hardware
- **Operating System:** Windows 10/11 x86_64, macOS (Apple Silicon / Intel), or Ubuntu Linux 22.04+
- **CPU:** Minimum 2 cores (Intel/AMD/Apple Silicon)
- **RAM:** Minimum 4 GB RAM (Aegis backend runs entirely under ~140 MB RSS on CPU via ONNX Runtime)
- **Disk:** 1 GB free space (including 255 MB DistilBERT ONNX model artifact)

### 1.2 Runtimes & Interpreters
- **Python Version:** Supported versions: **Python 3.10, 3.11, or 3.12 (64-bit)** (Python 3.11 recommended; Python 3.13 and 3.14 are **not supported** due to compiled C-extension constraints in `onnxruntime` and `pydantic-core`)
- **Node.js Version:** Node.js `v18.0.0` or higher (required for executing extension test suites)

### 1.3 Pinned Python Dependencies
The exact pinned virtual environment dependencies (`aegis-backend/.venv`) required to achieve deterministic numeric execution:

```
fastapi==0.141.1
uvicorn==0.52.4
httpx==0.28.1
onnxruntime==1.29.0
transformers==5.17.0
tokenizers==0.23.2
huggingface_hub==1.30.0
numpy==2.5.3
scikit-learn==1.9.1
xgboost==3.4.1
joblib==1.6.0
pydantic==2.13.5
python-dotenv==1.2.3
scipy==1.18.1
```

---

## 2. Environment Setup

### 2.1 Backend Virtual Environment
```powershell
# Navigate to backend root
cd aegis-backend

# Create virtual environment with Python 3.10–3.12 (e.g., using Windows Python Launcher)
py -3.12 -m venv .venv
# Or if python points to 3.10-3.12:
# python -m venv .venv

# Activate virtual environment
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# Linux / macOS:
# source .venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

### 2.2 Model Asset Verification
Verify that the pre-quantized DistilBERT ONNX weights and tokenizer vocabulary exist in `aegis-backend/models/phishing_distilbert/`:
```powershell
# From aegis-backend/
python -c "import hashlib, pathlib; p = pathlib.Path('models/phishing_distilbert/model.onnx'); print('SHA-256:', hashlib.sha256(p.read_bytes()).hexdigest())"
```
**Expected Model SHA-256:** `361ebc80a1aa7f48778ad007abed802f93fc807ffbd741e8661cf3837c200db0` (Size: 267,938,324 bytes)

---

## 3. Reproduction Commands & Exact Execution Seeds

All benchmark scripts are executed from the repository root: `Aegis-Phishing-Context-Analyzer/`.

### 3.1 Unit & Behavioral Test Suite (45/45 Behavioral)
```powershell
# Run the 45-test behavioral baseline verification suite
node aegis-extension/tests/test_behavioral_baseline.js
```
- **Expected Result:** `Behavioral Baseline Results: 45 passed, 0 failed.` (Exit Code: 0)

```powershell
# Run the full automated unit test suite (Extension + Backend)
python scratch/run_all_tests.py
```
- **Expected Result:** All tests pass across Behavioral (45), Whitelist (18), Auth extraction (6), Local heuristics (15), PII scrubber (14), Attachment hashes (5), and Backend routes (39).

### 3.2 Primary Phase C Full Pipeline Benchmark (E-08)
```powershell
python tools/run_phase_c_evaluations.py --commit 0c541f5
```
- **Dataset:** `aegis-backend/data/test_dataset.csv` (SHA-256: `e278c6004a02e2935d83895d5e8242fcd8df50bc9b46641a10dc9ac6721f9254`)
- **Composition:** Balanced 50 Phishing (`label='1'`) / 50 Legitimate (`label='0'`)
- **Fixed Seed:** `42`
- **Expected Metrics (Neutral Auth):**
  - Accuracy: `100.00%` (95% Wilson CI: `[96.3%, 100.0%]`)
  - Precision: `100.00%` | Recall: `100.00%` | FPR: `0.00%`
  - ROC-AUC: `1.0000`
  - Average Latency: `91.93 ms` (Median: `91.13 ms`, p95: `114.0 ms`)
  - Confusion Matrix: `TP=50, TN=50, FP=0, FN=0`
- **Output Artifacts:** `evidence/E-08_phishing-corpus-metrics/`

### 3.3 Four-Layer Defense Ablation Study (E-07)
Included in `tools/run_phase_c_evaluations.py`:
- **Execution:** Automated run across all 4 configurations:
  1. Heuristics Only (Layer 1)
  2. Heuristics + NLP (Layers 1 & 2)
  3. Heuristics + NLP + Behavioral (Layers 1, 2, 3)
  4. Full Pipeline (Layers 1, 2, 3, 4)
- **Output Artifacts:** `evidence/E-07_ablation/E-07_ablation_summary_20261108_0c541f5.csv`

### 3.4 Threshold Sensitivity Sweep (E-24)
Included in `tools/run_phase_c_evaluations.py`:
- **Threshold Range:** $T \in [20, 80]$ in steps of 5
- **Fixed Seed:** `42`
- **Output Artifacts:** `evidence/E-24_threshold-sweep/E-24_threshold-sweep_summary_20261108_0c541f5.csv`

### 3.5 Warning Cut-off Calibration on 200-Email Train Split (E-39)
```powershell
python tools/calibrate_warning_cutoff.py
```
- **Input Dataset:** `evidence/E-39_independent-corpus/E-39_dataset_train_200.csv`
- **Output Artifact:** `evidence/E-39_independent-corpus/E-39_train_calibration_report.json`
- **Harness Guard:** Automatically verifies `is_model_warm() == True` before execution, aborting with exit code 1 if DistilBERT is unprimed.

### 3.6 Independent External Corpora Multi-Set Evaluation (E-39, E-41, E-42, E-43)
```powershell
python tools/run_round2_evaluations.py --commit 11564ab
```
- **Datasets:** External Corpora (Jose Nazario, SpamAssassin, Enron)
- **Fixed Seed:** `42` (80/20 train/test stratified split)
- **Output Artifacts:** `evidence/E-39_round2_master_summary.json` and associated CSV records.

---

## 4. Non-Reproducible Steps & Architectural Disclosures

The following steps cannot be deterministically regenerated offline via automated script. The exact reasons are disclosed in compliance with academic transparency standards:

### 4.1 Live VirusTotal URL & File Hash Reputation (Layer 4)
- **Why It Cannot Be Fully Re-Run Offline:**
  1. **Quota Ceiling:** VirusTotal Free Tier enforces a strict rate limit of 4 requests/minute and 500 requests/day.
  2. **Dynamic Reputation Drift:** Cloud threat intelligence engines update threat scores, malware detection signatures, and domain blacklists continuously. A URL clean in October 2026 may be categorized as malicious months later.
  3. **Credential Requirement:** Requires an active private `VT_API_KEY` registered at VirusTotal.
- **Deterministic Workaround Provided:** Aegis provides pre-warmed offline seed caches (`aegis-backend/data/vt_seed_cache.json` and `vt_file_seed_cache.json`) that allow zero-network benchmark execution with fixed reputation verdicts.

### 4.2 Live Render Production Container Latency Telemetry
- **Why It Cannot Be Script-Regenerated Deterministically:**
  1. **Cloud Spin-Up Delays:** Render.com free-tier containers hibernate after 15 minutes of idle time. Cold-start latency depends on server host allocation, network congestion, and DNS propagation (measured empirically at 51.8s – 54.1s).
  2. **Network Jitter:** Round-trip times from client to Render Oregon (`us-west-1`) or Frankfurt data centers vary with public routing infrastructure.
- **Committed Empirical Telemetry:** Live empirical measurements capturing 3 cold wakeups and 30 warm inference requests are permanently committed in `evidence/E-45_small-fixes/live_render_telemetry_30warm_3cold_20261108_19affee.json`.

### 4.3 LLM-Authored Phishing Corpus Generation (E-43)
- **Why It Cannot Be Regenerated via Local Script:**
  1. **Commercial Model Drift:** The 60 test emails (30 phishing lures, 30 legitimate corporate emails) were generated using a commercial LLM session. Commercial API weights are proprietary, hosted remotely, and change across versions.
  2. **Safety Refusals:** LLM safety guardrails frequently refuse prompts requesting phishing email generation unless conducted under strict academic research framing.
- **Deterministic Workaround Provided:** The exact 60 generated email texts and evaluation predictions are frozen and committed in `evidence/E-43_llm-authored-eval/E-43_llm_predictions.csv`.

### 4.4 User Acceptance Testing (UAT) Empirical Survey Data (E-23)
- **Why It Cannot Be Regenerated via Script:**
  - UAT data reflects genuine human evaluation responses from 6 participants (owners and staff) across 3 Philippine small businesses evaluating prototype usability and workflow intrusiveness. Human survey responses cannot be regenerated programmatically.
- **Committed Data:** The fully anonymized participant data ($N=6$) and questionnaire analysis are committed in `evidence/E-23_uat-data/E-23_uat-data_anonymized_20261107_0c541f5.csv`.
