# Aegis Phishing Analyzer: Independent Reproduction Package (E-31)

- **Evidence ID:** E-31
- **Produced By:** I-16 / Open Science & Reproducibility Package
- **Commit:** `a482063`
- **Freeze Commit Tag:** `eval-freeze` (`91e1e8d`)
- **Specification:** AEGIS Implementation Plan v3.2 §4.2, §7 (I-16) & Post Defense Feedback

---

## 1. Package Overview

This reproduction package provides instructions, cryptographic digests, random seeds, and terminal commands to independently verify and reproduce all empirical evaluation results reported for the **Aegis Phishing Context Analyzer**.

All benchmarks execute strictly offline or locally without requiring live external API keys (VirusTotal layer held at offline baseline).

---

## 2. Environment Prerequisites

- **Workstation OS:** Windows 10 / 11 (64-bit)
- **Python Version:** Python 3.11+ (tested on Python 3.12.8)
- **Node.js:** Node.js 18+ (for extension unit tests)
- **Hardware Requirement:** x86_64 CPU with AVX2 support; minimum 8 GB RAM. (No GPU required; ONNX Runtime executes on CPU).

### Virtual Environment Setup

```bash
cd Aegis-Phishing-Context-Analyzer/aegis-backend
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Install dependencies:
pip install -r requirements.txt
```

---

## 3. Cryptographic Asset Verification

Verify that all model assets and evaluation datasets match the official cryptographic hashes recorded in `E-31_repro-package_hashes_20261107_a482063.txt`:

```bash
# Verify test dataset SHA-256
certutil -hashfile aegis-backend/data/test_dataset.csv SHA256
# Expected: e278c6004a02e2935d83895d5e8242fcd8df50bc9b46641a10dc9ac6721f9254

# Verify DistilBERT ONNX model checkpoint SHA-256
certutil -hashfile aegis-backend/models/phishing_distilbert_onnx_4cls/model.onnx SHA256
# Expected: 361ebc806085a3a411516091beae84eef050f22bf13b5ef2ba16d3f28d893d5f
```

---

## 4. Benchmark Execution Commands

### A. Full Phase C Evaluation Suite (E-07, E-08, E-24, E-34)
Executes all four post-defense benchmark evaluations (Full pipeline under neutral and synthetic auth, 4-config ablation with urgency-cue stripping, threshold sweep, and transactional FPR):

```bash
cd Aegis-Phishing-Context-Analyzer
python tools/run_phase_c_evaluations.py --commit a482063
```
- **Random Seed:** `42` (Fixed across all bootstrap and ablation passes)
- **Execution Time:** ~25 seconds on modern quad-core CPU.
- **Output Artifacts:** Generated into `evidence/E-07_ablation/`, `evidence/E-08_phishing-corpus-metrics/`, `evidence/E-24_threshold-sweep/`, `evidence/E-34_transactional-fpr/`.

### B. Unit & Integration Test Suites
Executes all 74 automated backend tests covering auth states (I-01), model loading guards (I-02), scoring formulas, and attachment heuristics:

```bash
cd Aegis-Phishing-Context-Analyzer/aegis-backend
pytest tests/ -v
# Expected: 74 passed in ~4.5s
```

Executes all 21 Chrome extension unit tests:

```bash
cd Aegis-Phishing-Context-Analyzer/aegis-extension
npm test
# Expected: 21 passed
```

### C. Evidence Manifest Strict Validation
Verifies cryptographic integrity and provenance of all evidence artifacts:

```bash
cd Aegis-Phishing-Context-Analyzer
python tools/evidence_manifest.py --dropped E-18,E-22,E-35,E-37,E-38
# Expected: 0 errors, 0 warnings
```
