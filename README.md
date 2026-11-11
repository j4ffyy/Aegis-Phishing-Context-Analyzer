# AEGIS: An Exploratory Phishing Context Analysis Decision-Support Framework for Small and Medium Enterprises

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20%7C%20Uvicorn-009688.svg)](https://fastapi.tiangolo.com/)
[![ONNX Runtime](https://img.shields.io/badge/Inference-ONNX%20Runtime%20(%7E140MB%20RSS)-005CED.svg)](https://onnxruntime.ai/)
[![Chrome Extension](https://img.shields.io/badge/Chrome%20Extension-Manifest%20V3-4285F4.svg)](https://developer.chrome.com/docs/extensions/mv3/)
[![Status](https://img.shields.io/badge/Status-Academic%20Proof--of--Concept-orange.svg)]()

> **Mapúa Malayan Digital College (MMDC)**  
> **Course:** MO-IT200D2 — Capstone 2 (Academic Year 2026–2027)  
> **Degree Program:** Bachelor of Science in Information Technology, Major in Network & Cyber Security  
> **Proponents:** **Jafphet P. Grengia** & **Michael Angelo L. Bernardo**  
> **Mentor / Adviser:** **Mr. Rhimshie Jay Aquino**  
> **Program Head / Supervisory Review:** **Mr. Mario Pison Jr.**  
> **Panel Evaluators:** **Mr. John Ray Hernani** (Panel Chair) & **Mr. Renz Canlas** (Panel Member)  
> **Revised Manuscript (Post-Defense):** November 2026

---

## 🛡️ Project Overview & Positioning

Phishing attacks remain a persistent cyber threat to Small and Medium Enterprises (SMEs) in the Philippines, which often depend on consumer-grade email services and lack dedicated security personnel or Security Operations Centers (SOCs).

**AEGIS** is an **exploratory academic proof-of-concept framework** designed for explainable, context-aware phishing decision support on **desktop Gmail** (`https://mail.google.com/*`) in Chromium-based browsers (Google Chrome, Microsoft Edge, Brave). 

### Architectural Boundary & Scope
- **Advisory DOM-Based Overlay:** AEGIS observes email rendered in the active browser DOM using a client-side `MutationObserver` (with a 300 ms debounce).
- **No Mailbox State Alteration:** AEGIS does **not** interact with Gmail's internal APIs, IMAP/POP3 protocols, or server-side mail storage. It **cannot quarantine, delete, move, or block emails**. Visual risk badges are advisory decision-support aids for the active user.
- **Data Sovereignty & Privacy Posture:** On-device behavioral baselines (Layer 3) and custom whitelists are stored exclusively in `chrome.storage.local` and never leave the browser. Sanitized email text (with best-effort client-side PII scrubbing on email body text) is transmitted over HTTPS to the FastAPI backend service for inference. *A formal compliance audit under Republic Act No. 10173 (Data Privacy Act of 2012) was not conducted and is disclaimed.*

---

## 🏛️ System Architecture

```text
┌────────────────────────────────────────────────────────────────────────┐
│             CHROMIUM BROWSER (Chrome, Edge, Brave)                     │
│                                                                        │
│  ┌───────────────────────┐             ┌─────────────────────────────┐ │
│  │    mail.google.com    │             │       AEGIS Extension       │ │
│  │   (Active Email DOM)  │◀────────────│  (Content Script & Overlay) │ │
│  └───────────┬───────────┘             └──────────────┬──────────────┘ │
│              │                                        │                │
│              ▼ (DOM Mutation, 300ms debounce)         ▼                │
│     [1. Gmail DOM Extractor]               [chrome.storage.local]      │
│              │                                        │                │
│              ▼                                        ├── Whitelist    │
│     [2. PII Scrubber (Best-effort)]                   └── L3 Baseline  │
│              │                                                         │
│              ▼                                                         │
│     [3. Local Heuristic & Offline Fallback Engine]                     │
└──────────────┼─────────────────────────────────────────────────────────┘
               │ POST /api/v1/analyze (Sanitized Payload + L3 Score)
               ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   AEGIS BACKEND (FastAPI / Render)                     │
│                                                                        │
│  ┌───────────────────────────────┐   ┌───────────────────────────────┐ │
│  │ Layer 1: Heuristics & ML      │   │ Layer 2: DistilBERT ONNX      │ │
│  │ (RF + XGBoost Ensemble,       │   │ (4-Class Semantic Inference,  │ │
│  │  Typosquatting, 21 Brands)    │   │  Frozen Static Checkpoint)    │ │
│  └───────────────┬───────────────┘   └───────────────┬───────────────┘ │
│                  │                                   │                 │
│                  └─────────────────┬─────────────────┘                 │
│                                    ▼                                   │
│                      [Meta-Classifier & Synthesis]                     │
│               Composite = 0.25·L1 + 0.45·L2 + 0.15·L3 + 0.15·L4         │
│                                    │                                   │
│                  ┌─────────────────┴─────────────────┐                 │
│                  ▼                                   ▼                 │
│  ┌───────────────────────────────┐   ┌───────────────────────────────┐ │
│  │ Layer 3: Behavioral Ingestion │   │ Layer 4: VirusTotal Gateway   │ │
│  │ (Client-computed Circular L3) │   │ (Async Rate-Paced Link & Hash)│ │
│  └───────────────────────────────┘   └───────────────────────────────┘ │
│                                    │                                   │
│                                    ▼                                   │
│                [Two-Tier Explainable AI (XAI) Engine]                  │
│                - Tier 1: Plain-Language Summary (Default)              │
│                - Tier 2: Technical View Panel & Modal                  │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ JSON Analysis Response
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│  AEGIS Risk Overlay (In-Gmail HUD: Gauge, Tier Badge, Two-Tier XAI)    │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🔬 Detection Pipeline & Composite Scoring

Aegis synthesizes heterogeneous signals using a weighted linear combination of four analytical layers:

$$S_{\text{composite}} = \min\left(100, \text{round}\left(0.25 \cdot S_{\text{heuristic}} + 0.45 \cdot S_{\text{nlp}} + 0.15 \cdot S_{\text{behavioral}} + 0.15 \cdot S_{\text{vt}}\right)\right)$$

| Layer | Component | Weight | Analytical Scope & Implementation |
| :---: | :--- | :---: | :--- |
| **L1** | **Heuristics & Ensemble ML** | **25%** | Rule-based heuristics combined with a Random Forest and XGBoost ensemble ($S_{\text{layer1}} = 0.60 \cdot S_{\text{heuristic}} + 0.40 \cdot S_{\text{ensemble}}$). Evaluates URL structure, 21 protected brands (10 PH banks/wallets, 3 government, 2 e-commerce, 6 global), Levenshtein edit distance, and Tagalog/Taglish urgency lexicons (33 patterns). |
| **L2** | **DistilBERT NLP Classifier** | **45%** | Pre-trained frozen ONNX sequence classifier (`lemonade-sdk/phishing-email-detection-distilbert-ONNX`, Apache-2.0) served via ONNX Runtime (~140 MB RSS). Evaluates semantic context and urgency tone. |
| **L3** | **On-Device Behavioral Baseline** | **15%** | Evaluated on-device in `chrome.storage.local`. Measures sender novelty (first-time sender = 25) and circadian hour distance ($d_H > 6\text{h} = +20$). Does not upload interaction history to the cloud. |
| **L4** | **Threat Intelligence** | **15%** | VirusTotal v3 API for URL reputation and attachment SHA-256 hash lookup (15-second rate pacing lock; free-tier quota-aware). |

### Risk Tiers & Preset Thresholds

```text
  0 ──────────── 44 ────────────────────── 74 ─────────────────── 100
 [     SAFE        ] [       WARNING         ] [     CRITICAL        ]
   (Green Overlay)        (Amber Overlay)           (Red Overlay)
```

- **Safe (0–44)**: Routine benign communication; verified sender and clean content.
- **Warning (45–74)**: Anomalous signals detected (e.g., first-time sender, urgency markers).
- **Critical (75–100)**: Corroborated malicious indicators (e.g., confirmed VirusTotal threat hit, spoofed executive identity).
- **Heuristic Floors**: A minimum score of **52 (Warning)** is enforced when compound attachment/urgency cues or high heuristic scores ($S_h \ge 40$) occur.
- **Guided Sensitivity Presets**:
  - **Conservative (High Protection):** Warning $\ge 35$, Critical $\ge 65$ (recommended for financial/executive inboxes).
  - **Standard (Default):** Warning $\ge 45$, Critical $\ge 75$ (balanced SME workflow).
  - **Aggressive (Low Alert Volume):** Warning $\ge 55$, Critical $\ge 85$ (requires strong multi-layer corroboration).

---

## 📊 Summary of Empirical Results

| Evaluation Corpus | Size | Full Pipeline Recall | False Positive Rate | Key Empirical Finding |
| :--- | :---: | :---: | :---: | :--- |
| **Controlled Template Set (Phase C)** | $N=100$ | **100.0%** (CI 92.9–100%) | **0.0%** (CI 0.0–7.1%) | End-to-end pipeline feasibility confirmed with model confirmed loaded. |
| **Independent Public Corpus (Test Split)** | $N=50$ | **32.0%** (CI 17.2–51.6%) | **0.0%** (CI 0.0–13.3%) | Fixed 45 cut-off failed on older/cleaner public mail ($\text{ROC-AUC} = 1.000$; 12% on Nazario phishing). |
| **Philippine / Taglish Test Set** | $N=60$ | **86.7%** (CI 70.3–94.7%) | **10.0%** (CI 3.5–25.6%) | High regional sensitivity; lift driven primarily by heuristic keyword adjustments. |
| **LLM-Authored Phishing Set** | $N=60$ | **13.3%** (CI 5.3–29.7%) | **0.0%** (CI 0.0–11.3%) | Polished AI text evades fixed thresholds; **detection of AI phishing not demonstrated**. |
| **User Acceptance Testing (UAT)** | $N=6$ | — | — | Mean rating **4.67 / 5.00**; owners (4.33) vs. staff (5.00) highlighted an IT-literacy gap. |

---

## 🚀 Evaluation & Setup Guide for Advisers and Panelists

This guide details how to install, inspect, and test the AEGIS proof-of-concept extension on desktop Google Chrome.

### Prerequisites
- **Google Chrome**, **Microsoft Edge**, or **Brave Browser** (Chromium-based with Manifest V3 support)
- Active internet connection (for cloud backend analysis and VirusTotal lookups)

---

### Step 1: Load the Chrome Extension

1. Open Google Chrome and enter `chrome://extensions/` in the address bar.
2. In the top-right corner, toggle **Developer mode** to **ON**.
3. In the top-left corner, click **Load unpacked**.
4. In the file picker, select the `aegis-extension` folder from this repository:
   ```text
   .../Aegis-Phishing-Context-Analyzer/aegis-extension
   ```
5. You will see **Aegis: AI-Powered Phishing Context Analyzer** appear in your extension list.

---

### Step 2: Backend Connectivity & Cold-Start Notice

The extension is pre-configured to communicate with the live cloud backend:
- **Production Backend Endpoint:** `https://aegis-backend-oybm.onrender.com`
- **Fallback / Local Endpoint:** `http://localhost:8000`

> [!IMPORTANT]
> **Render.com Free-Tier Cold-Start Delay (~50 seconds):**  
> If the backend has been idle, the initial cloud request may take **50–55 seconds** to spin up the container. If this timeout window elapses during the very first scan, AEGIS gracefully transitions into **Offline Heuristic Mode** (amber banner). Once the backend container wakes up, subsequent scans execute in **< 1.0 second**.  
> *Tip:* You can wake the container in advance by opening [`https://aegis-backend-oybm.onrender.com/api/v1/health`](https://aegis-backend-oybm.onrender.com/api/v1/health) in a browser tab before testing.

---

### Step 3: Testing in Desktop Gmail

1. Open **[mail.google.com](https://mail.google.com)** on desktop Chrome.
2. Select any email in your inbox.
3. Upon opening the message, AEGIS's `MutationObserver` triggers after a 300 ms debounce:
   - An advisory **Risk Score Badge** (Safe / Warning / Critical) and gauge appear in the overlay.
   - **Tier 1 (Default):** Displays a plain-language summary designed for non-technical SME employees (e.g., Sender Legitimacy, Message Tone).
   - **Tier 2 (Technical View Toggle):** Click the **"Technical View"** switch to inspect low-level indicators, including SPF/DKIM validation status (*Fail, Pass, or Not verified*), PII redaction tallies, behavioral circular hour metrics, and per-layer scores.
4. Open the **Settings Panel / Dashboard** from the extension popup or overlay to inspect the **Guided Sensitivity Presets** (*Conservative*, *Standard*, *Aggressive*).

---

### Step 4: Optional Local Backend Execution

If you wish to run the backend locally instead of relying on the cloud service:

```powershell
# Navigate to backend directory
cd aegis-backend

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt

# Start local server on port 8000
python -m uvicorn main:app --reload --port 8000
```

Verify local health: [`http://localhost:8000/api/v1/health`](http://localhost:8000/api/v1/health)

---

## 👥 Academic Credits & Acknowledgment

| Role | Name | Affiliation |
| :--- | :--- | :--- |
| **Researcher / Proponent** | **Jafphet P. Grengia** | Mapúa Malayan Digital College |
| **Researcher / Proponent** | **Michael Angelo L. Bernardo** | Mapúa Malayan Digital College |
| **Capstone Mentor / Adviser** | **Mr. Rhimshie Jay Aquino** | Mapúa Malayan Digital College |
| **Program Head / Revision Review** | **Mr. Mario Pison Jr.** | Mapúa Malayan Digital College |
| **Panel Chair** | **Mr. John Ray Hernani** | Panel Evaluator |
| **Panel Member** | **Mr. Renz Canlas** | Panel Evaluator |

---

## 📄 Academic Citation & License

Developed in partial fulfillment of the requirements for the degree of **Bachelor of Science in Information Technology (Major in Network and Cyber Security)** at **Mapúa Malayan Digital College (MMDC)**. Released under the [MIT License](LICENSE).
