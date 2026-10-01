# Aegis: Setup & Chrome Extension Run Guide

Welcome to **Aegis: AI-Powered Phishing Context Analyzer**. This guide provides end-to-end instructions for setting up the project from a fresh `git clone`, installing all dependencies, starting the local inference backend, loading the unpacked extension into Google Chrome, and verifying that the real-time phishing analysis pipeline works as intended.

---

## Architecture Overview

Aegis is composed of two primary cooperating subsystems:

1. **`aegis-backend`** (Python / FastAPI):
   - Fast, lightweight inference API running locally at `http://localhost:8000`.
   - Hosts a self-contained **DistilBERT ONNX** NLP classification model (`models/phishing_distilbert/`).
   - Runs the multi-layered threat engine: heuristic weighting, link scanning (VirusTotal API + seed cache), and explainable AI (XAI) rationale generation.
2. **`aegis-extension`** (Chrome Extension Manifest V3):
   - Privacy-first client-side content script running directly on [mail.google.com](https://mail.google.com).
   - Scrubs PII (Philippine DPA RA 10173 compliant) before sending anonymized features to the backend.
   - Injects a high-fidelity, non-intrusive risk badge and analysis overlay directly into the Gmail interface.
   - Includes a persistent local sender whitelist and behavioral baseline engine (`chrome.storage.local`).

*(A standalone mock email client is also provided in `Aegis_Prototype/index.html` for offline demonstrations and defense presentations).*

```
┌────────────────────────────────────────────────────────┐
│                   Google Chrome                        │
│                                                        │
│  ┌───────────────────────┐   ┌──────────────────────┐  │
│  │    mail.google.com    │   │   Aegis Extension    │  │
│  │   (Active Email DOM)  │◀──│ (Content Script & UI)│  │
│  └───────────┬───────────┘   └──────────┬───────────┘  │
│              │                          │              │
│              ▼                          ▼              │
│       [PII Scrubber]             [Local Cache /        │
│       [L1 Heuristics]             Whitelist]           │
└──────────────┼──────────────────────────┼──────────────┘
               │                          │
      POST /api/v1/analyze                │
               │                          │
               ▼                          ▼
┌────────────────────────────────────────────────────────┐
│             Aegis Backend (FastAPI :8000)              │
│  ┌─────────────────────────┐ ┌──────────────────────┐  │
│  │ DistilBERT ONNX Engine  │ │  VirusTotal Scanner  │  │
│  └─────────────────────────┘ └──────────────────────┘  │
│  ┌──────────────────────────────────────────────────┐  │
│  │          Meta-Classifier & XAI Generator         │  │
│  └──────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────┘
```

---

## Prerequisites

Before starting, ensure your system has the following installed:

| Tool | Version | Purpose |
| :--- | :--- | :--- |
| **Google Chrome** | v109+ (M115+ recommended) | Browser to run the Manifest V3 extension |
| **Python** | 3.10, 3.11, or 3.12 | Backend server runtime (Python 3.11 recommended) |
| **Git** | Latest | Source control to clone the repository |
| **Node.js** *(Optional)* | v18+ | Optional, only needed to run extension unit tests |
| **VirusTotal API Key** *(Optional)* | Free Tier | Optional for live URL reputation queries |

---

## Quick-Start Checklist

1. [Clone Repository](#step-1-clone-the-repository)
2. [Configure & Start Backend](#step-2-set-up-and-run-the-backend)
3. [Load Extension into Google Chrome](#step-3-load-the-extension-into-google-chrome)
4. [Test in Gmail](#step-4-test-aegis-in-google-chrome)
5. [Verify with Automated Tests](#step-5-verifying-your-setup-optional)

---

## Step 1: Clone the Repository

Open your terminal (PowerShell, Command Prompt, or Terminal) and clone the repository:

```bash
git clone https://github.com/j4ffyy/Aegis-Phishing-Context-Analyzer.git
cd Aegis-Phishing-Context-Analyzer
```

Verify that the project structure includes:
```text
Aegis-Phishing-Context-Analyzer/
├── aegis-backend/       # FastAPI backend server
├── aegis-extension/     # Manifest V3 Chrome Extension
├── Aegis_Prototype/     # Standalone offline web demo
├── docs/                # Architecture and capstone documentation
└── README.md
```

---

## Step 2: Set Up and Run the Backend

The backend performs deep NLP classification and meta-scoring. Setting it up requires creating a virtual environment, installing dependencies, downloading the ONNX model, and starting Uvicorn.

### 2.1 Navigate to the Backend Directory
```bash
cd aegis-backend
```

### 2.2 Create a Python Virtual Environment

- **On Windows (PowerShell):**
  ```powershell
  python -m venv .venv
  ```
  *If you encounter a script execution restriction in PowerShell, enable it for this process:*
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  .\.venv\Scripts\Activate.ps1
  ```

- **On Windows (Command Prompt `cmd`):**
  ```cmd
  python -m venv .venv
  .\.venv\Scripts\activate.bat
  ```

- **On macOS / Linux:**
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  ```

When active, your terminal prompt will show `(.venv)`.

### 2.3 Install Python Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

> **Note on Architecture:** Aegis uses **ONNX Runtime (CPU)** instead of raw PyTorch. This keeps server RAM below 150MB, avoiding out-of-memory crashes and allowing it to run smoothly on any laptop or free-tier cloud host.

### 2.4 Configure Environment Variables (`.env`)
Copy the provided `.env.example` file to `.env`:

- **Windows (PowerShell):**
  ```powershell
  Copy-Item .env.example .env
  ```
- **macOS / Linux / Bash:**
  ```bash
  cp .env.example .env
  ```

Open `.env` in any text editor. It contains:
```ini
# Aegis Backend — Environment Variables

# Optional: VirusTotal free-tier API key (from https://www.virustotal.com/gui/join-us)
# If omitted or left as default, Aegis safely uses its built-in URL seed cache
VT_API_KEY=your_virustotal_api_key_here

# Allowed CORS Origin for local development (wildcard allows local extension requests)
CORS_ORIGIN=*

# Deployment environment: "development" | "production"
ENVIRONMENT=development
```

### 2.5 Download the DistilBERT ONNX Model Assets
The NLP model weights are intentionally excluded from git due to file size. Run the automated model downloader script to fetch the fine-tuned DistilBERT ONNX model and tokenizer from Hugging Face:

```bash
python scripts/download_model.py
```

You should see output similar to:
```text
[Aegis Build] Baking ONNX model and tokenizer from lemonade-sdk/phishing-email-detection-distilbert-ONNX...
[Aegis Build]   Completed config.json
[Aegis Build]   Downloading model.onnx (~255 MB)...
[Aegis Build]   Completed model.onnx
[Aegis Build]   Completed tokenizer.json
[Aegis Build]   Completed vocab.txt
```
This stores the model assets inside `aegis-backend/models/phishing_distilbert/`.

### 2.6 Start the FastAPI Server
Launch the development server with live reload enabled:

```bash
uvicorn main:app --reload --port 8000
```

Verify the server started:
```text
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     [Aegis NLP] DistilBERT ONNX session and tokenizer loaded successfully from phishing_distilbert
INFO:     [Aegis LinkScanner] Loaded 3 entries into VirusTotal seed cache.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

### 2.7 Verify Backend Health
Open your browser or run curl to test the endpoints:
- **Health check:** [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health) (returns `{"status": "ok", "nlp_model_loaded": true, ...}`)
- **Interactive API Docs:** [http://localhost:8000/docs](http://localhost:8000/docs) (Swagger UI)

> **Keep this terminal window open** while using the extension so the local AI server remains active.

---

## Step 3: Load the Extension into Google Chrome

Now that your inference backend is running, install the client extension into Google Chrome.

### 3.1 Open the Chrome Extensions Page
1. Launch **Google Chrome**.
2. Type `chrome://extensions` in the address bar and press **Enter**.

### 3.2 Enable Developer Mode
In the upper-right corner of the `chrome://extensions` page, switch the **Developer mode** toggle to **ON**.

```
┌──────────────────────────────────────────────────────────────┐
│ Extensions                              [ Developer mode ◉ ] │
│ ┌────────────────┐ ┌───────────────┐ ┌───────────────┐       │
│ │  Load unpacked │ │  Pack extension│ │  Update      │       │
│ └────────────────┘ └───────────────┘ └───────────────┘       │
└──────────────────────────────────────────────────────────────┘
```

### 3.3 Load the Unpacked Extension
1. Click the **Load unpacked** button in the top-left corner.
2. In the folder selection dialog, navigate to the cloned project folder:
   ```text
   C:\...\Aegis-Phishing-Context-Analyzer\aegis-extension
   ```
3. Select the **`aegis-extension`** directory and click **Select Folder**.

### 3.4 Confirm Installation
You will now see the Aegis extension card:
- **Name:** `Aegis: AI-Powered Phishing Context Analyzer`
- **Version:** `0.1.0`
- **Description:** *Privacy-preserving phishing detection for SME Gmail users...*
- **Inspect views:** `service worker` (clickable link to open background logs)

### 3.5 Pin the Extension (Recommended)
1. Click the **Extensions puzzle icon** (🧩) in the top-right toolbar of Chrome.
2. Find **Aegis Phishing Analyzer** and click the **Pin** icon (📌).
3. The Aegis shield icon will now remain visible on your Chrome toolbar.

---

## Step 4: Test Aegis in Google Chrome

### Method A: Live Gmail Testing

1. Open [mail.google.com](https://mail.google.com) in your Chrome browser.
2. Log into your Google account (any personal or SME workspace account).
3. **Open any email** in your inbox.
4. **Observe the Aegis Detection Flow**:
   - The content script detects that an email has been opened via its debounced `MutationObserver`.
   - The Aegis **Analysis Shield Badge** appears immediately at the top of the email thread or reading pane.
   - Aegis performs:
     1. Client-side PII scrubbing (phone numbers, personal emails, sensitive tokens are masked).
     2. Layer 1 heuristic pattern checks (sender anomalies, display-name spoofing, urgent keywords).
     3. Checks the sender against your local Chrome whitelist.
     4. Dispatches an asynchronous request to `http://localhost:8000/api/v1/analyze`.
     5. Displays the composite risk score (`0-100`), threat level (`SAFE`, `SUSPICIOUS`, or `CRITICAL`), and plain-language XAI rationale explaining why the email is safe or flagged.
5. **Interactive Controls inside the Email**:
   - Click the **Details / Expand** toggle on the overlay to view individual risk layer breakdowns (Heuristics, Behavioral Baseline, NLP DistilBERT, VirusTotal Link Scanner).
   - Click **"Trust Sender"** / **"Add to Whitelist"** to instantly whitelist the sender domain.
   - Click **"Re-scan"** to force a fresh analysis.

---

### Method B: Testing Extension Popup & Whitelist Dashboard

1. Click the **Aegis icon** in your Chrome toolbar.
2. The popup interface will appear with:
   - **Status Indicator:** Shows whether Aegis is currently active and monitoring Gmail.
   - **Refresh Gmail Tab:** Reloads your active Gmail tab and re-triggers analysis.
   - **Whitelist Dashboard:** Opens `chrome-extension://<id>/whitelist/whitelist_dashboard.html`, where you can view, add, or delete whitelisted domains and senders.
   - **Restart Aegis Runtime:** Reloads the background service worker.

---

### Method C: Offline Testing via Prototype (No Gmail Account Required)

If you wish to test or demonstrate the detection interface without opening your private Gmail inbox:

1. In Chrome, press `Ctrl + O` (or `Cmd + O` on macOS).
2. Browse to and open:
   ```text
   Aegis-Phishing-Context-Analyzer/Aegis_Prototype/index.html
   ```
3. This opens the self-contained mock email client showcasing four representative attack scenarios:
   - **Email 1:** Legitimate Internal HR Memo (Safe baseline).
   - **Email 2:** Malicious Security Certificate Scam with embedded phishing link (Critical).
   - **Email 3:** High-Urgency Wire Transfer / BEC Scam from external spoofed address (Suspicious).
   - **Email 4:** Invoice notification with suspicious attachment (Critical).

---

## Step 5: Verifying Your Setup (Optional)

You can run automated tests across both the backend and extension to ensure all components are functioning properly.

### Running Backend Unit Tests
From the `aegis-backend/` directory with `.venv` active:
```bash
pytest
```
*Expected result:* All test suites pass (tests cover DistilBERT inference, meta-classifier scoring, VirusTotal caching, and `/api/v1/analyze` endpoints).

### Running Extension Unit Tests
From the `aegis-extension/` directory (requires Node.js):
```bash
node tests/test_pii_scrubber.js
node tests/test_local_heuristics.js
node tests/test_whitelist.js
node tests/test_behavioral_baseline.js
node tests/test_background_bridge.js
```
*Expected result:* `[PASS]` for all test assertions.

---

## Troubleshooting & Common Questions

### 1. PowerShell: "Running scripts is disabled on this system"
**Cause:** Windows PowerShell default execution policy blocks activating `.venv`.  
**Fix:** Run this command once in your current PowerShell window before activating:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### 2. "Failed to fetch" or Aegis Badge displays "Backend Offline / Fallback Mode"
**Cause:** The FastAPI backend is not running, or is running on a port other than `8000`.  
**Fix:**
1. Check your terminal where `uvicorn` was started. Ensure it states `Uvicorn running on http://127.0.0.1:8000`.
2. Visit [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health) directly in Chrome.
3. *Note:* If the backend is intentionally shut down, Aegis is designed to continue protecting users via **Layer 1 Client-Side Heuristics** and displays a degraded fallback banner.

### 3. Port 8000 is already in use
**Cause:** Another application (e.g., another Python server or web proxy) is occupying port `8000`.  
**Fix (Windows):**
```powershell
# Identify process using port 8000
netstat -ano | findstr :8000
# Kill process by PID (replace <PID>)
taskkill /F /PID <PID>
```
Alternatively, run uvicorn on another port and update `DEFAULT_BACKEND_URL` in `aegis-extension/background.js`.

### 4. Updating Code & Reloading the Extension
If you modify JavaScript, HTML, or CSS files in `aegis-extension`:
1. Go to `chrome://extensions`.
2. Locate **Aegis: AI-Powered Phishing Context Analyzer**.
3. Click the **circular reload icon** (🔄) on the Aegis card.
4. Refresh your [mail.google.com](https://mail.google.com) tab (`F5` or `Ctrl + R`).

### 5. Inspecting Debug Logs
- **Content Script / Overlay Logs:** On Gmail, press `F12` to open Chrome DevTools. Navigate to the **Console** tab. Filter by `[Aegis` to inspect extraction events, PII scrub counts, and UI rendering logs.
- **Background Service Worker Logs:** Go to `chrome://extensions`, locate Aegis, and click the **`service worker`** link under "Inspect views". A dedicated DevTools window will open displaying all network bridge and caching logs.

---

## Project Repository Links

- **Backend Entry Point:** [aegis-backend/main.py](file:///c:/Users/jafph/Desktop/Capstone%201%20-%20Phishing%20Analyzer/Aegis-Phishing-Context-Analyzer/aegis-backend/main.py)
- **Extension Manifest:** [aegis-extension/manifest.json](file:///c:/Users/jafph/Desktop/Capstone%201%20-%20Phishing%20Analyzer/Aegis-Phishing-Context-Analyzer/aegis-extension/manifest.json)
- **Extension Content Script:** [aegis-extension/content_script.js](file:///c:/Users/jafph/Desktop/Capstone%201%20-%20Phishing%20Analyzer/Aegis-Phishing-Context-Analyzer/aegis-extension/content_script.js)
- **Offline Prototype:** [Aegis_Prototype/index.html](file:///c:/Users/jafph/Desktop/Capstone%201%20-%20Phishing%20Analyzer/Aegis-Phishing-Context-Analyzer/Aegis_Prototype/index.html)
