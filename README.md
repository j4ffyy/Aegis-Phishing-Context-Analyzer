# Aegis: AI-Powered Phishing Context Analyzer for Small and Medium Enterprises

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20%7C%20Uvicorn-009688.svg)](https://fastapi.tiangolo.com/)
[![ONNX Runtime](https://img.shields.io/badge/Inference-ONNX%20Runtime%20(%3C150MB%20RSS)-005CED.svg)](https://onnxruntime.ai/)
[![Chrome Extension](https://img.shields.io/badge/Chrome%20Extension-Manifest%20V3-4285F4.svg)](https://developer.chrome.com/docs/extensions/mv3/)
[![Tests](https://img.shields.io/badge/Automated%20Tests-108%20Passed%20(100%25)-success.svg)]()
[![Compliance](https://img.shields.io/badge/Data%20Privacy-RA%2010173%20(PH%20DPA)-brightgreen.svg)]()

> **MMDC IT200D1 — Capstone Project 1**  
> **Institution:** Mapúa Malayan Digital College (MMDC)  
> **Proponents:** **Jafphet P. Grengia** (Lead Developer / UX Lead) & **Michael Angelo L. Bernardo** (Co-Developer / Systems Lead)  
> **Capstone Adviser:** **Mr. Ryan Dalmacio**

---

## 🛡️ Executive Summary

Small and Medium Enterprises (SMEs) in the Philippines face disproportionate exposure to targeted phishing, Business Email Compromise (BEC), and credential harvesting attacks. Unlike large enterprises with Security Operations Centers (SOCs), SMEs operate under severe budgetary and technical personnel constraints. Furthermore, legacy email gateways act as black-box filters, offering binary allow/block decisions without actionable, contextual explanations.

**Aegis** is an intelligent, privacy-preserving browser security layer delivered as a **Google Chrome Extension (Manifest V3)** paired with a **self-hosted private machine learning backend (FastAPI)**. Aegis intercepts emails directly within the user's webmail interface (Gmail), evaluates threat signals across a **4-layer contextual pipeline**, and provides plain-language **Explainable AI (XAI)** threat rationales through a non-disruptive overlay interface.

To satisfy national privacy mandates under the **Philippine Data Privacy Act of 2012 (Republic Act No. 10173)**, Aegis enforces strict client-side personally identifiable information (PII) redaction prior to any inter-process communication or remote processing.

---

## 🏛️ System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        GOOGLE CHROME BROWSER                           │
│                                                                        │
│  ┌───────────────────────┐             ┌─────────────────────────────┐ │
│  │    mail.google.com    │             │       Aegis Extension       │ │
│  │   (Active Email DOM)  │◀────────────│  (Content Script & Overlay) │ │
│  └───────────┬───────────┘             └──────────────┬──────────────┘ │
│              │                                        │                │
│              ▼                                        ▼                │
│     [1. DOM Extractor]                      [Client Storage Local]     │
│              │                                        │                │
│              ▼                                        ├── Whitelist    │
│     [2. PII Scrubber (RA 10173)]                      └── Behavioral   │
│              │                                                         │
│              ▼                                                         │
│     [3. Local Heuristics & Offline Baseline Engine]                    │
└──────────────┼─────────────────────────────────────────────────────────┘
               │ POST /api/v1/analyze (Anonymized Payload)
               ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    AEGIS BACKEND (FastAPI :8000)                       │
│                                                                        │
│  ┌───────────────────────────────┐   ┌───────────────────────────────┐ │
│  │ Layer 1: Heuristic Engine     │   │ Layer 2: DistilBERT ONNX      │ │
│  │ (Spoofing, Typosquatting,     │   │ (Semantic Intent Inference,   │ │
│  │  Attachment Intelligence)     │   │  <150 MB RSS Memory Ceiling)  │ │
│  └───────────────┬───────────────┘   └───────────────┬───────────────┘ │
│                  │                                   │                 │
│                  └─────────────────┬─────────────────┘                 │
│                                    ▼                                   │
│                      [Meta-Classifier & Synthesis]                     │
│                      (Synthesized Risk Score 0-100%)                   │
│                                    │                                   │
│                  ┌─────────────────┴─────────────────┐                 │
│                  ▼                                   ▼                 │
│  ┌───────────────────────────────┐   ┌───────────────────────────────┐ │
│  │ Layer 3: Behavioral Baseline  │   │ Layer 4: VirusTotal Gateway   │ │
│  │ (Circadian Hour Delta Anomaly)│   │ (Async Rate-Paced Link Scan)  │ │
│  └───────────────────────────────┘   └───────────────────────────────┘ │
│                                    │                                   │
│                                    ▼                                   │
│                   [Plain-Language XAI Generator]                       │
│                   (Actionable Security Guidance)                       │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ JSON Analysis Response
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│  Aegis Risk Overlay (In-Gmail HUD: Gauge, Layer Status, XAI Rationale) │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🔬 Multi-Layer Contextual Scoring Engine

Aegis synthesizes heterogeneous signals into a single unified threat score:

$$R_{\text{final}} = \min\left(100, \text{round}\left(w_1 S_{\text{heuristic}} + w_2 S_{\text{nlp}} + w_3 S_{\text{behavioral}} + w_4 S_{\text{vt}}\right)\right)$$

| Layer | Component | Weight ($w_i$) | Analytical Focus |
| :---: | :--- | :---: | :--- |
| **L1** | **Heuristic & Spoofing** | **25%** | Domain typosquatting (Levenshtein), deceptive hyperlinks, IP hosts, suspicious TLDs, and executable/archive attachments. |
| **L2** | **DistilBERT NLP Intent** | **45%** | Fine-tuned transformer executed via ONNX Runtime (<150 MB RSS) evaluating semantic urgency, financial coercion, and intent. |
| **L3** | **Behavioral Baseline** | **15%** | Sender familiarity frequency and circadian timing anomalies using circular clock distance: $d_H(h_1, h_2) = \min(\|h_1 - h_2\|, 24 - \|h_1 - h_2\|)$. |
| **L4** | **VirusTotal Intelligence** | **15%** | Rate-paced URL reputation scanner with an asynchronous 15.0s pacing lock, dual cache keyspaces, and offline seed lookup. |

### Threat Tiers & Warning Floor
- **Safe (0–44%)**: Routine benign communications; verified sender and expected timing.
- **Warning (45–69%)**: Anomalous indicators detected; precautionary inspection recommended.
- **Critical (70–100%)**: Active phishing, credential harvesting, dangerous attachment, or executive impersonation.
- **Multi-Indicator Threat Floor (§6.5)**: When compound indicators are flagged (e.g., suspicious attachment combined with urgency signals), Aegis bounds the minimum score to **52% (Warning)**, preventing threat dilution when external links or sender history are absent.

---

## 🔒 Privacy & Compliance (RA 10173)

In compliance with the **Philippine Data Privacy Act of 2012 (RA 10173)**, Aegis executes client-side token redaction directly within the content script context before any data exits the browser:
- Personal Names $\rightarrow$ `[NAME]`
- Email Addresses $\rightarrow$ `[EMAIL]`
- Telephone Numbers $\rightarrow$ `[PHONE]`
- Payment Card Numbers $\rightarrow$ `[CARD_NUMBER]` *(Luhn algorithm validated)*
- Government IDs (SSS, TIN, PhilHealth, US SSN) $\rightarrow$ `[SSN]`

Zero raw email body content is logged to disk or stored remotely.

---

## 📂 Repository Structure

```text
Aegis-Phishing-Context-Analyzer/
├── aegis-backend/                   # Private inference server (FastAPI)
│   ├── main.py                      # Application entrypoint & lifespan warmup
│   ├── routes/                      # API endpoints (/analyze, /health, /vt-status)
│   ├── modules/                     # Core detection engines
│   │   ├── heuristic_engine.py      # Rule-based heuristics & typosquatting
│   │   ├── nlp_classifier.py        # DistilBERT ONNX runtime inference
│   │   ├── behavioral_analyzer.py   # Anomaly scoring & circular time delta
│   │   ├── link_scanner.py          # Rate-paced VirusTotal v3 gateway
│   │   └── meta_classifier.py       # 4-layer risk synthesis & XAI generator
│   ├── models/phishing_distilbert/  # Pre-baked ONNX model weights & tokenizer
│   ├── data/                        # VirusTotal seed cache & evaluation datasets
│   └── tests/                       # Pytest/unittest backend test suite (34 tests)
│
├── aegis-extension/                 # Chrome Extension (Manifest V3)
│   ├── manifest.json                # Least-privilege MV3 declaration
│   ├── content_script.js            # Gmail DOM extraction & MutationObserver
│   ├── background.js                # Service Worker: API bridge, LRU cache & TTL
│   ├── pii_scrubber.js              # Client-side PII redaction engine (RA 10173)
│   ├── local_heuristics.js          # Autonomous offline fallback engine
│   ├── overlay/                     # In-page risk HUD & Full Analysis modal
│   │   ├── overlay.html             # Modal structure
│   │   ├── overlay.js               # Dynamic gauge, icon embedding & XAI logic
│   │   └── overlay.css              # Glassmorphic dark/light UI design system
│   ├── whitelist/                   # SME administrative whitelist dashboard
│   ├── icons/                       # Shield logo assets (16px, 48px, 128px)
│   └── tests/                       # Extension test suites (74 tests)
│
├── demo_emails/                     # Standardized evaluation test corpus
│   ├── 01_SAFE_routine_workplace.md
│   ├── 02_WARNING_archive_attachment.md
│   ├── 03_CRITICAL_credential_harvesting_link.md
│   ├── 04_CRITICAL_malicious_html_attachment.md
│   ├── 05_CRITICAL_executive_impersonation_bec.md
│   └── attachments/                 # Safe & simulated malicious test files
│
├── Aegis_Prototype/                 # Standalone offline web demo (no Gmail needed)
├── docs/                            # Research papers, presentation guides & plans
├── start_backend.bat                # Windows one-click backend launcher
├── SETUP_GUIDE.md                   # Comprehensive step-by-step installation guide
└── README.md                        # Project documentation (this file)
```

---

## 🚀 Quick Start Guide

> 📖 **For complete step-by-step instructions, see the [SETUP_GUIDE.md](SETUP_GUIDE.md).**

### Prerequisites
- **Google Chrome** v109+ (Manifest V3 support)
- **Python** 3.10, 3.11, or 3.12 (Python 3.11 recommended)
- **Git**

---

### Step 1: Clone the Repository
```bash
git clone https://github.com/j4ffyy/Aegis-Phishing-Context-Analyzer.git
cd Aegis-Phishing-Context-Analyzer
```

---

### Step 2: Launch the Backend Server

#### Option A: One-Click Launcher (Windows)
Double-click `start_backend.bat` in the root folder, or run:
```cmd
start_backend.bat
```

#### Option B: Manual Setup
```bash
cd aegis-backend
python -m venv .venv

# Activate Virtual Environment:
# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# macOS / Linux:
source .venv/bin/activate

# Install Dependencies:
pip install -r requirements.txt

# Download Model Assets (if not already baked into models/):
python scripts/download_model.py

# Start Server:
uvicorn main:app --reload --port 8000
```
Verify the server is running by opening: [`http://localhost:8000/api/v1/health`](http://localhost:8000/api/v1/health)

---

### Step 3: Load the Extension into Google Chrome

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (toggle in the top-right corner).
3. Click **Load unpacked** (top-left).
4. Select the `aegis-extension` folder from the repository.
5. The **Aegis Phishing Context Analyzer** extension is now active!

---

### Step 4: Test in Gmail

1. Open [mail.google.com](https://mail.google.com).
2. Open any email thread.
3. The Aegis **Shield Icon** will analyze the email and display the risk assessment badge and overlay HUD.
4. Click **"View Full Analysis"** for detailed XAI rationales and layer breakdown.
5. You can also test with the provided scenarios in the [`demo_emails/`](demo_emails/) folder.

---

## 🧪 Automated Testing & Empirical Verification

Aegis includes comprehensive test suites across both subsystems with **108 total automated tests** passing at 100%:

```bash
# 1. Run Backend Unit & Integration Tests (34 tests)
cd aegis-backend
.\.venv\Scripts\python.exe -m unittest discover -s tests

# 2. Run Extension Unit Tests (74 tests)
cd ../aegis-extension
node tests/test_local_heuristics.js    # 12 tests: typosquatting, IPs, attachments
node tests/test_pii_scrubber.js        # 14 tests: RA 10173 PII redaction, Luhn check
node tests/test_behavioral_baseline.js # 30 tests: circular hour delta, novelty scoring
node tests/test_whitelist.js           # 18 tests: dual-trigger auto-revocation
```

| Component | Test Suite | Tests Run | Result |
| :--- | :--- | :---: | :---: |
| **Backend Subsystem** | `aegis-backend/tests/` | 34 | ✅ **PASSED** |
| **Local Heuristics** | `tests/test_local_heuristics.js` | 12 | ✅ **PASSED** |
| **PII Redaction (RA 10173)** | `tests/test_pii_scrubber.js` | 14 | ✅ **PASSED** |
| **Behavioral Baseline** | `tests/test_behavioral_baseline.js` | 30 | ✅ **PASSED** |
| **Whitelist Auto-Revocation** | `tests/test_whitelist.js` | 18 | ✅ **PASSED** |
| **Total Automated Tests** | **Full System** | **108** | ✅ **100% PASS** |

---

## 👥 Project Team & Credits

| Role | Proponent | Institution |
| :--- | :--- | :--- |
| **Lead Developer / UX Lead** | **Jafphet P. Grengia** | Mapúa Malayan Digital College |
| **Co-Developer / Systems Lead** | **Michael Angelo L. Bernardo** | Mapúa Malayan Digital College |
| **Capstone Project Adviser** | **Mr. Ryan Dalmacio** | Mapúa Malayan Digital College |

---

## 📄 Academic Citation & License

Developed as part of **IT200D1 — Capstone Project 1** at Mapúa Malayan Digital College (MMDC). Released under the [MIT License](LICENSE).
