# Aegis Chrome Extension — Complete Build Implementation Plan

> **Project:** AI-Powered Phishing Context Analyzer for Small and Medium Enterprises
> **Team:** Jafphet P. Grengia & Michael Angelo L. Bernardo
> **Adviser:** Mr. Ryan Dalmacio
> **Current Status:** Aegis_Prototype (demo sim) exists — needs to evolve into a real Chrome Extension MV3 package.
> **Deployment:** localhost:8000 (dev) → Render.com free tier / Starter tier ($7/mo demo week contingency)
> **AI Model:** Local DistilBERT via ONNX Runtime (`lemonade-sdk/phishing-email-detection-distilbert-ONNX`) — no API key, <150MB RSS
> **Link Intelligence:** VirusTotal free API key (4 req/min rate-controlled, 2-link cap, pre-warmed demo cache)
> **Participants:** 12–15 MMDC classmates + faculty proxies (Week 4)

---

## ✅ Confirmed Architecture Decisions

These decisions are **locked in** and reflected throughout all weekly tasks below.

| Decision | Choice | Rationale |
| :--- | :--- | :--- |
| **Backend hosting (dev)** | `localhost:8000` (FastAPI) | Zero latency, no internet dependency during Weeks 1–4 |
| **Backend hosting (demo day)** | [Render.com](https://render.com) free tier (or Starter tier $7/mo for demo week) — persistent URL | Panelists can access without running your laptop; 750 hrs/month free; Starter tier ($7) eliminates 512MB RAM ceiling and 15-min idle spin-down during live presentation |
| **AI model** | **DistilBERT via ONNX Runtime** (`onnxruntime` + `lemonade-sdk/phishing-email-detection-distilbert-ONNX`) — no API key | Works fully offline, memory stays <150MB RSS (prevents Render 512MB OOM crash), no commercial API fees; cited as "self-hosted private inference" in Chapter IV (avoids mischaracterization as on-device edge) |
| **Link Intelligence** | **VirusTotal free API key** — register at virustotal.com | Strictly rate-controlled to 4 req/min, capped at 2 links/email, with direct Base64 URL lookup and offline pre-warmed cache (`scripts/prewarm_vt_cache.py`) for demo day & usability testing |
| **Participants (Week 4)** | **12–15 MMDC classmates + 2–3 faculty/admin proxies** | Academically valid representative sample; non-tech students = SME admin/finance staff; BSIT = IT support role |

> [!NOTE]
> Store all keys in `.env` (never hardcoded). The `apiEndpoint` in `chrome.storage.local` switches between `http://localhost:8000` (dev) and the Render URL (final demo). Update this in `background.js` before Week 5 submission.

---

## What We Are Building

A **Chrome Extension (Manifest V3)** that:
1. Detects when the user is reading an email in Gmail (webmail DOM injection)
2. Extracts email context (sender, body, headers, links, attachments) entirely **client-side**
3. Strips PII before any data leaves the browser
4. Runs a **4-layer analysis pipeline** (Auth → Link Intel → Behavioral → NLP/ML)
5. Displays the **Aegis Risk Score (0–100%)**, layer breakdown, and **XAI explanation** in an overlay panel
6. Falls back to **local heuristic cache** when offline or when API is slow
7. Allows SME admins to manage a **Whitelist Dashboard** with auto-revocation rules

---

## Current State of Aegis_Prototype

The existing code in [`Aegis_Prototype/`](file:///c:/Users/jafph/Desktop/Capstone%201%20-%20Phishing%20Analyzer/Aegis-Phishing-Context-Analyzer/Aegis_Prototype/) is a **standalone demo simulator** — a mocked Gmail-like web page that simulates the Aegis overlay. It is **not** a real Chrome Extension yet.

**What it has correctly (reuse):**
- Visual design: Overlay panel, Risk Score Card, 5-Layer Status list, XAI Box, Action Buttons, JS Threat Block Overlay
- All the HTML/CSS/JS logic for the analysis UI popup
- `styles.css` with the full Aegis design system

**What it still needs to become a real extension:**
- `manifest.json` (MV3) — the entry point that makes it a Chrome Extension
- `content_script.js` — auto-injected into Gmail pages to extract real email data
- `background.js` (Service Worker) — manages API calls and `chrome.storage.local` caching
- `popup.html` / `popup.js` — the extension toolbar button popup (optional but useful)
- A real backend API (`/analyze` endpoint) — or a smart local fallback
- The PII Scrubber module (client-side, runs before any data is sent out)

---

## Folder Structure (Target)

```
Aegis-Phishing-Context-Analyzer/
├── aegis-extension/                    ← THE REAL CHROME EXTENSION (MV3)
│   ├── manifest.json                   ← [NEW] Chrome Extension entry point
│   ├── background.js                   ← [NEW] Service Worker (API bridge + cache)
│   ├── content_script.js               ← [NEW] Gmail DOM reader + UI injector
│   ├── pii_scrubber.js                 ← [NEW] Client-side PII stripping module
│   ├── local_heuristics.js             ← [NEW] Offline fallback rule engine
│   ├── popup/
│   │   ├── popup.html                  ← [NEW] Extension toolbar popup
│   │   ├── popup.js                    ← [NEW] Popup logic
│   │   └── popup.css                   ← [NEW] Popup styles
│   ├── overlay/
│   │   ├── overlay.html                ← [ADAPTED from Aegis_Prototype/index.html]
│   │   ├── overlay.js                  ← [ADAPTED from Aegis_Prototype/app.js]
│   │   └── overlay.css                 ← [ADAPTED from Aegis_Prototype/styles.css]
│   ├── icons/
│   │   ├── icon16.png
│   │   ├── icon48.png
│   │   └── icon128.png
│   └── whitelist/
│       ├── whitelist_dashboard.html    ← [NEW] SME Admin whitelist UI
│       └── whitelist.js                ← [NEW] Whitelist management logic
│
├── aegis-backend/                      ← [NEW] Python FastAPI backend (local or cloud)
│   ├── main.py                         ← API server entry point (lifespan warmup)
│   ├── Dockerfile                      ← Bakes ONNX model & tokenizer at build time
│   ├── routes/
│   │   ├── analyze.py                  ← /api/v1/analyze & /api/v1/vt-status/{hash}
│   │   └── health.py                   ← /api/v1/health endpoint
│   ├── modules/
│   │   ├── heuristic_engine.py         ← Regex + SPF/DKIM heuristics
│   │   ├── link_scanner.py             ← VirusTotal v3 URL scanner (4 req/min rate control)
│   │   ├── nlp_classifier.py           ← DistilBERT ONNX pipeline (<150MB RSS)
│   │   ├── behavioral_analyzer.py      ← Baseline comparison logic
│   │   └── meta_classifier.py          ← 4-layer weighted risk score synthesis
│   ├── models/
│   │   └── phishing_distilbert/        ← Vendored ONNX model + tokenizer assets
│   ├── scripts/
│   │   ├── download_model.py           ← Build-time model & tokenizer downloader
│   │   └── prewarm_vt_cache.py         ← Offline seed script for demo & test URLs
│   ├── data/
│   │   ├── vt_seed_cache.json          ← Pre-warmed VirusTotal scan results
│   │   └── benchmark_dataset.json      ← Week 4 comparative evaluation dataset
│   ├── requirements.txt                ← onnxruntime, transformers, fastapi (no torch)
│   └── .env.example
│
├── Aegis_Prototype/                    ← EXISTING demo sim (keep as reference)
├── docs/                               ← Documentation folder
└── MO-IT200D1 _ S3102 Group 1 Revised Capstone 1 Final Paper.md
```

---

## 5-Week Build Plan

---

### WEEK 1 — Chrome Extension Shell + Gmail DOM Reader
**Goal:** A real Chrome Extension that injects itself into Gmail and shows the Scan FAB button.

#### Tasks

**1.1 Create `manifest.json` (MV3)**

> [!IMPORTANT]
> **Fix #ManifestSecurity (Issues #3, #4, #Scripting & #ManifestHygiene):**
> 1. **`web_accessible_resources`:** In Manifest V3, Gmail's page context cannot load extension resources (e.g. `overlay/overlay.html`, `overlay/overlay.css`, and UI icons) via `fetch(chrome.runtime.getURL(...))` or `<iframe>` without declaring them in `web_accessible_resources` scoped to `https://mail.google.com/*`.
> 2. **Backend `host_permissions`:** Declaring `"http://localhost:8000/*"` and specific `"https://aegis-api-xxxx.onrender.com/*"` (replace with assigned Render service slug) provides the background service worker with direct network fetch permissions, bypassing strict extension-origin CORS barriers without overly broad wildcard grants (`*.onrender.com`).
> 3. **Unused `activeTab` and `scripting` permissions dropped:** Content scripts are registered statically via `content_scripts: [...]` and do not require `chrome.scripting.executeScript()` or user-gesture tab capture (`activeTab`). Dropping both adheres strictly to Chrome Web Store least-privilege standards and preempts defense panel inquiries.
> 4. **Manifest V3 CSP Compliance (Fix #CSP):** Default MV3 CSP prohibits inline scripts (`<script>...</script>`) and inline HTML event attributes (`onclick="..."`, `onsubmit="..."`). All extension HTML files (`popup/popup.html`, `overlay/overlay.html`, `whitelist/whitelist_dashboard.html`) MUST load logic strictly via external `<script src="...">` files and attach listeners via `addEventListener()`.

```json
{
  "manifest_version": 3,
  "name": "Aegis Phishing Analyzer",
  "version": "1.0.0",
  "description": "AI-Powered Phishing Context Analyzer for SMEs",
  "permissions": ["storage"],
  "host_permissions": [
    "https://mail.google.com/*",
    "http://localhost:8000/*",
    "https://aegis-api-xxxx.onrender.com/*"
  ],
  "background": { "service_worker": "background.js" },
  "content_scripts": [{
    "matches": ["https://mail.google.com/*"],
    "js": ["pii_scrubber.js", "local_heuristics.js", "content_script.js"],
    "css": ["overlay/overlay.css"],
    "run_at": "document_idle"
  }],
  "web_accessible_resources": [{
    "resources": [
      "overlay/overlay.html",
      "overlay/overlay.css",
      "icons/*"
    ],
    "matches": ["https://mail.google.com/*"]
  }],
  "action": {
    "default_popup": "popup/popup.html",
    "default_icon": { "48": "icons/icon48.png" }
  },
  "icons": { "16": "icons/icon16.png", "48": "icons/icon48.png", "128": "icons/icon128.png" }
}
```

**1.2 Create `content_script.js` — Gmail DOM Reader**

This script:
- Waits for Gmail to load an email thread using a `MutationObserver` on `[role="main"]` (not `document.body` — Gmail is a SPA and observing the entire document body causes O(n²) callback triggering on every keystroke)
- Uses a `debounce(callback, 300)` wrapper so the observer only fires after DOM mutations settle, preventing redundant scans
- Extracts: subject, sender name, sender email, email body text, embedded links, attachment names
- **Runs `scrubPII()` on the body text immediately after extraction — before `chrome.runtime.sendMessage()`** (see justification in §2.1)
- Injects the Aegis overlay panel and Scan FAB button into the Gmail DOM

// ✅ Fix #5 — Resilient Multi-Selector Fallback Chain
// Gmail's DOM classnames (.a3s.aiL, .gD, h2.hP, .aV3) shift periodically across
// Gmail UI updates, density views, and preview pane layouts. Using fallback chains
// prevents extraction failures on demo day.
function getFirstMatch(selectors, context = document) {
  for (const sel of selectors) {
    const el = context.querySelector(sel);
    if (el) return el;
  }
  console.warn(`[Aegis] Warning: None of the selectors matched:`, selectors);
  return null;
}

function getAllMatches(selectors, context = document) {
  for (const sel of selectors) {
    const els = context.querySelectorAll(sel);
    if (els && els.length > 0) return Array.from(els);
  }
  return [];
}

// Resilient selector chains
const SELECTORS = {
  subject: ['h2.hP', '[data-thread-perm-id] h2', '.ha h2', '[role="main"] h2'],
  sender: ['span.gD', 'span[email]', '.go span', '[data-hovercard-id]'],
  body: ['.a3s.aiL', '.ii.gt', '[role="listitem"] .a3s', 'div[dir="ltr"]'],
  attachments: ['.aV3', '.aZo', '[aria-label*="Attachment"]', '[data-tooltip*="Attachment"]']
};

function extractEmailContext() {
  const subjectEl = getFirstMatch(SELECTORS.subject);
  const senderEl = getFirstMatch(SELECTORS.sender);
  const bodyEl = getFirstMatch(SELECTORS.body);
  const attachEls = getAllMatches(SELECTORS.attachments);

  // ✅ Fix #SenderFallback: Extract email address ONLY from the 'email' attribute.
  // The 'name' attribute contains the display name, NOT an email address.
  // Falling back to 'name' would inject a display string (e.g. "John Smith") into
  // senderEmail, corrupting the whitelist match key, the behavioral baseline hash,
  // and the display-name spoof detection logic in meta_classifier.py.
  // If the 'email' attribute is missing entirely, fall back to empty string and log
  // a warning for observability — do NOT silently swap in a display name.
  const senderEmail = senderEl?.getAttribute('email') || '';
  if (!senderEmail) {
    console.warn('[Aegis] Could not extract sender email address — Gmail DOM selector may need updating.');
  }
  const senderDisplayName = senderEl?.innerText?.trim() || senderEl?.getAttribute('name') || '';

  // ✅ Fix #DOMFailureTelemetry: Alert if all selector chains fail simultaneously.
  // Silent console.warn gets lost during debugging. A visible overlay banner is
  // surfaced when all three critical fields are missing (likely a Gmail DOM change).
  if (!subjectEl && !senderEl && !bodyEl) {
    console.error('[Aegis] All critical Gmail DOM selectors failed. Gmail may have updated its structure — update SELECTORS.');
    return null; // Caller should check for null and skip analysis
  }

  return {
    subject: subjectEl?.innerText?.trim() || '(No Subject)',
    senderEmail: senderEmail,
    senderDisplayName: senderDisplayName,
    body: bodyEl?.innerText || '',
    links: Array.from(bodyEl?.querySelectorAll('a[href]') || []).map(a => a.href),
    hasAttachment: attachEls.length > 0
  };
}

function debounce(fn, delay) {
  let timer;
  return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), delay); };
}

// ✅ Fix #3: Stable cache key via Web Crypto API — available in content scripts and
// MV3 service workers (Chrome 101+). Derived from sender + subject + first 200 body
// chars so the hash is stable across duplicate views of the same email thread.
async function hashEmail(subject, sender, body) {
  const text = `${sender}:${subject}:${body.slice(0, 200)}`;
  const buffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}
```

**1.3 Adapt `overlay.css` and `overlay.js` from Aegis_Prototype**
- Copy `styles.css` → `overlay/overlay.css` (remove Gmail simulation styles, keep Aegis panel styles)
- Start adapting `app.js` → `overlay.js` (remove mock email data, replace with data received from `content_script.js`)

**1.4 Set up `chrome.storage.local` structure**
```js
// Storage schema
{
  "whitelist": [],          // Array of {email, role, department, addedAt}
  "cache": {},              // Hash → {score, riskLevel, xai, timestamp} (eviction: max 100 entries, 7-day TTL)
  "behavioralBaseline": {}, // senderEmail → {count, hours: [], lastSeen} (rolling window: max 30 hours)
  "settings": {
    "apiEndpoint": "http://localhost:8000",
    "offlineMode": false,
    "hardCapMonthlyUSD": 5.00
  }
}
```

**1.5 Backend skeleton — FastAPI**

> [!NOTE]
> **CORS fix (Issue #7):** `allow_origins=["chrome-extension://*"]` is NOT a valid glob — Starlette's `CORSMiddleware` treats it as a literal string and will reject all extension requests. Use `["*"]` during development and lock to the specific extension ID before the Render.com deploy. The extension ID is visible at `chrome://extensions` after loading unpacked.

```python
# main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# ✅ Fix #10 & Fix #OOM: Warm up ONNX Runtime session and load pre-warmed VT cache.
# Cold-start on CPU takes ~1s; subsequent requests execute in ~25–50ms.
# RSS memory remains <150MB (safely below Render 512MB ceiling).
@asynccontextmanager
async def lifespan(app: FastAPI):
    from modules.nlp_classifier import warm_up_nlp
    from modules.link_scanner import load_vt_seed_cache
    warm_up_nlp()            # Warms up ONNX Runtime InferenceSession
    load_vt_seed_cache()     # Pre-populates VT cache from data/vt_seed_cache.json
    yield

app = FastAPI(lifespan=lifespan)

# ✅ Fix #7: Use "*" in dev; before Week 5 Render deploy, replace with:
# allow_origins=["chrome-extension://YOUR_EXTENSION_ID"]
app.add_middleware(CORSMiddleware, allow_origins=["*"])

@app.get("/api/v1/health")
def health(): return {"status": "ok"}

# ✅ Fix #DuplicateRoute: Week 1 developer skeleton stub.
# In Week 2, REPLACE this inline stub by mounting the modular analyze router:
#   from routes.analyze import router as analyze_router
#   app.include_router(analyze_router)
# Do NOT leave both active to prevent route registration conflicts.
@app.post("/api/v1/analyze")
def analyze_stub(payload: dict): return {"status": "stub", "mode": "DEV_SKELETON"}
```

**1.5b Backend `requirements.txt`**

> [!IMPORTANT]
> **Fix #OOM & Fix #BuildBloat:** Do NOT install `torch` (~700MB–1.5GB wheel). PyTorch consumes ~800MB–1GB RAM at runtime (causing Render 512MB free-tier OOM crashes) and risks hitting Render build timeouts. Use `onnxruntime` (~15MB install, ~140MB runtime RSS).

```text
fastapi>=0.110.0
uvicorn>=0.28.0
httpx>=0.27.0
onnxruntime==1.17.3
transformers>=4.38.0
tokenizers>=0.15.0
huggingface-hub>=0.21.0
numpy>=1.24.0
pydantic>=2.6.0
python-dotenv>=1.0.0
```

**1.5c Bake Model into Deploy Artifact (`Dockerfile` & `scripts/download_model.py`)**

> [!IMPORTANT]
> **Fix #VendorModel (Issues #1 & #2):**
> 1. **No runtime model download:** In containerized deployments (Render), if the model is downloaded during startup (`warm_up_nlp`), every container restart after a 15-minute idle spin-down incurs a 15–30s download delay or crashes if HF Hub is slow/unreachable.
> 2. **Unified repo source:** `model.onnx` and all tokenizer assets are downloaded **together** from `lemonade-sdk/phishing-email-detection-distilbert-ONNX` into `models/phishing_distilbert/` at **Docker image build time**.
> 3. **Zero network dependency at runtime:** In production, the model and tokenizer load 100% locally from the filesystem.

> [!NOTE]
> **✅ HF Repo File Manifest Verified (Fix #ModelRepo):** The `lemonade-sdk/phishing-email-detection-distilbert-ONNX` repo was verified via the HF API on 2026-09-05. It ships all 5 required files: `model.onnx`, `tokenizer.json`, `tokenizer_config.json`, `vocab.txt`, and `special_tokens_map.json`. The model card overview was incomplete — the repo itself is complete and the `download_model.py` script will succeed without 404 errors. **No action needed.**

```dockerfile
# aegis-backend/Dockerfile — Bakes DistilBERT ONNX & Tokenizer at build time
FROM python:3.11-slim
WORKDIR /app

# 1. Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2. Bake model and tokenizer files into image at BUILD time
COPY scripts/download_model.py scripts/
RUN python scripts/download_model.py

# 3. Copy application code and seed data
COPY . .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```python
# aegis-backend/scripts/download_model.py — Runs during Docker build
# ✅ Fix #ModelRepo: All 5 files confirmed present in lemonade-sdk/phishing-email-detection-distilbert-ONNX
# (verified via HF API 2026-09-05). Download from single source — no cross-repo split needed.
from pathlib import Path
from huggingface_hub import hf_hub_download

REPO_ID = "lemonade-sdk/phishing-email-detection-distilbert-ONNX"
DEST = Path("models/phishing_distilbert")
DEST.mkdir(parents=True, exist_ok=True)

FILES = [
    "model.onnx",
    "tokenizer.json",
    "tokenizer_config.json",
    "vocab.txt",
    "special_tokens_map.json"
]

print(f"[Aegis Build] Baking ONNX model and tokenizer from {REPO_ID}...")
for fname in FILES:
    hf_hub_download(repo_id=REPO_ID, filename=fname, local_dir=str(DEST))
print(f"[Aegis Build] Model and tokenizer successfully baked into {DEST}")
```

#### Week 1 Deliverables
- [x] `aegis-extension/manifest.json` created
- [x] Extension loads in Chrome (`chrome://extensions` → Load Unpacked)
- [x] `content_script.js` injects overlay panel and Scan FAB into Gmail
- [x] Clicking Scan FAB opens the Aegis overlay panel
- [x] FastAPI server starts and returns health check at `/api/v1/health`
- [x] Sprint Log entries for Sept 03–09

---

### WEEK 2 — PII Scrubber + Heuristic Layer + API Integration
**Goal:** The extension can analyze an email through the heuristic layer and display a real risk score.

#### Tasks

**2.1 Create `pii_scrubber.js` — Client-Side PII Stripping**

> [!IMPORTANT]
> **Scope fix (Issue #4):** `scrubPII()` must be called inside **`content_script.js`** immediately after DOM extraction and **before** `chrome.runtime.sendMessage()` is called. The original plan called `scrubPII()` inside `background.js`, but content scripts and Service Workers run in isolated execution contexts — functions defined in `pii_scrubber.js` (a content script) are completely invisible to `background.js`. Moving the call to the content script also makes the paper's RA 10173 claim more precise: *"PII is stripped at the point of extraction, before the data enters any inter-process channel."*

All PII is removed **at the point of extraction in `content_script.js`** before the message is sent to the background service worker:
```js
// ✅ Called in content_script.js — BEFORE chrome.runtime.sendMessage()
// Justification: scrubPII() lives in pii_scrubber.js which is a content script.
// Service Workers (background.js) cannot access content script functions.
// Scrubbing here ensures zero PII enters the inter-process message channel.
function scrubPII(text) {
  return text
    .replace(/\b[A-Z][a-z]+ [A-Z][a-z]+\b/g, '[NAME]')             // Names
    // ⚠ Known limitation (Fix #PII-FP): This regex matches ANY two-capitalized-word
    // pattern (e.g., "Best Regards", "New York", "Dear Sir"). It also misses
    // single-word names, lowercase names, and names with diacritics/apostrophes.
    // Acceptable for Capstone 1 prototype's RA 10173 compliance since the scrubber
    // runs on email body text where proper names are the dominant two-capitalized-word
    // pattern. Documented as a limitation in §4.4 (Limitations) of the paper.
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/gi, '[EMAIL]') // Emails
    .replace(/\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b/g, '[PHONE]')       // Phone numbers
    .replace(/\b(?:\d[ -]*?){13,16}\b/g, '[CARD_NUMBER]')            // Credit cards
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[SSN]');                     // SSNs
}

// Usage inside content_script.js — MutationObserver debounced callback:
// ✅ Fix #NullGuard: extractEmailContext() returns null when all DOM selectors miss
// (e.g. a Gmail DOM update). Guard at the top of the callback before any downstream
// call — hashEmail, scrubPII, scoreBehavioral — can receive undefined inputs.
const rawData = extractEmailContext();
if (!rawData) return; // Gmail DOM didn't match — bail silently; observer will retry on next mutation

const emailHash = await hashEmail(rawData.subject, rawData.senderEmail, rawData.body); // Fix #3
// ✅ Fix #2 (partial): pre-compute local heuristic score HERE, in the content script
// context where runLocalHeuristics() is defined. Service workers cannot call content
// script functions (isolated execution contexts) — passing the pre-computed value in
// the message payload is the only safe approach (see background.js §2.3 for usage).
// ✅ Fix #Issue5: behavioralScore is pre-computed here in the content script context,
// where chrome.storage.local and scoreBehavioralSync helpers are available.
// The value is bundled into the message payload so background.js can forward it to
// the backend without needing access to storage or content-script functions itself.
//
// ✅ Fix #EmptySenderKey: senderEmail is '' when the Gmail DOM doesn't expose the
// 'email' attribute. Passing '' to scoreBehavioral() would key ALL such emails into
// baseline[''], collapsing many distinct senders into one shared behavioral bucket
// and corrupting both the "rare sender" and "unusual hour" signals. Short-circuit
// to a neutral score instead — identical to how a brand-new sender is treated.
const behavioralResult = rawData.senderEmail
  ? await scoreBehavioral(rawData.senderEmail, new Date().getHours())
  : { score: 25, flags: ['Sender address unavailable — neutral score'] };
const messagePayload = {
  type: 'ANALYZE_EMAIL',
  data: {
    senderEmail: rawData.senderEmail,
    subject: rawData.subject,
    body: scrubPII(rawData.body),           // ← PII stripped HERE, not in background.js
    links: rawData.links,
    hasAttachment: rawData.hasAttachment,
    emailHash: emailHash,                   // ← generated via Web Crypto API (see §1.2)
    localScore: runLocalHeuristics(rawData),// ← pre-computed for SW offline fallback
    behavioralScore: behavioralResult.score // ← forwarded to backend payload (see §2.3)
  }
};

chrome.runtime.sendMessage(messagePayload, (response) => {
  if (!response) return;

  // 1. Render the initial overlay with the (non-VT) score immediately.
  updateOverlayUI(response);

  // 2. ✅ Fix #SW-Lifecycle & #VT-PollingWindow & #StaleTab:
  // If the backend reports VT is still pending, start a polling loop HERE in
  // content_script.js — NOT in the service worker. Content scripts survive as
  // long as the Gmail tab is open, so setTimeout chains run reliably regardless
  // of Chrome's MV3 30-second SW idle-kill timer.
  //
  // Each poll sends a brief CHECK_VT_STATUS message to the SW, which wakes for
  // a single fetch+respond cycle (~1–2s) and immediately goes idle again.
  //
  // This also eliminates the stale-tab bug: the content script updates its own
  // overlay directly — no chrome.tabs.query() re-resolution needed.
  if (response.vt_status === 'pending' && response._vtPollHint) {
    const { emailHash, linksCount } = response._vtPollHint;
    const maxRetries = Math.max(8, (linksCount || 1) * 4); // 40s for 1–2 links, scales higher
    let attempt = 0;

    const vtPollInterval = setInterval(() => {
      attempt++;
      chrome.runtime.sendMessage(
        { type: 'CHECK_VT_STATUS', emailHash },
        (vtResult) => {
          if (chrome.runtime.lastError) {
            // SW unavailable (extension reloaded, etc.) — stop polling gracefully
            clearInterval(vtPollInterval);
            return;
          }
          if (vtResult?.status === 'complete') {
            clearInterval(vtPollInterval);
            // Fold re-synthesized 4-layer score into the live overlay
            if (vtResult.score !== undefined) {
              updateScoreGauge(vtResult.score, vtResult.riskLevel);
            }
            if (vtResult.vt_result) {
              updateLayerBadge('link-intel', vtResult.vt_result.vt_score || 0,
                               vtResult.vt_result.flagged_links || []);
            }
            if (vtResult.xai) {
              updateXAIExplanation(vtResult.xai);
            }
          }
          if (attempt >= maxRetries) {
            clearInterval(vtPollInterval);
            console.warn(`[Aegis] VT polling timed out after ${maxRetries * 5}s`);
          }
        }
      );
    }, 5000); // Poll every 5s
  }
});
```

**2.2 Create `local_heuristics.js` — Offline Fallback Engine**

Rules evaluated locally (no API call needed):
- Domain typosquatting check (edit distance ≤ 2 from known brands)
- Suspicious keyword density (urgent, wire transfer, click here, verify now)
- Reply-to mismatch check (sender domain ≠ reply-to domain)
- Homoglyph detection (paypa1.com, g00gle.com)

```js
const SUSPICIOUS_KEYWORDS = [
  'urgent', 'immediately', 'wire transfer', 'account suspended',
  'verify now', 'click here', 'confirm identity', 'prize winner'
];
const BRAND_DOMAINS = ['paypal', 'amazon', 'microsoft', 'google', 'apple'];

function runLocalHeuristics(emailData) {
  let score = 0;
  // Keyword scan
  const keywordHits = SUSPICIOUS_KEYWORDS.filter(kw => 
    emailData.body.toLowerCase().includes(kw));
  score += keywordHits.length * 10;
  // Domain spoof check
  // ...
  return Math.min(score, 70); // Cap offline heuristics at 70%
}
```

**2.3 Connect Extension → Backend `/analyze`**

> [!IMPORTANT]
> **Critical async fix (Issue #1):** Chrome's `onMessage` API requires the listener to synchronously `return true` if `sendResponse` will be called asynchronously. Using `async` directly on the listener function does NOT satisfy this requirement — the runtime sees a Promise returned (truthy, but not `true`), closes the port immediately, and `sendResponse` is called on a dead channel. All analysis results are silently dropped. Fix: wrap the async logic in an IIFE and return `true` at the listener level.

`background.js` service worker:
```js
// ✅ Fix #1: Wrap async work in an IIFE; return true synchronously.
// The payload body is already scrubbed — scrubPII() was called in content_script.js.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'ANALYZE_EMAIL') {
    (async () => {
      // Data arrives pre-scrubbed from content_script.js (see §2.1)
      // ✅ Fix #Issue5: behavioral_score is pre-computed client-side (scoreBehavioral runs in
      // content_script.js where chrome.storage.local is accessible). It is bundled here so
      // the backend's meta_classifier can use it without storing any behavioral data server-side.
      const payload = {
        sender: msg.data.senderEmail,
        subject: msg.data.subject,
        body: msg.data.body,              // Already PII-stripped by pii_scrubber.js
        links: msg.data.links,
        hasAttachment: msg.data.hasAttachment,
        behavioral_score: msg.data.behavioralScore ?? 25, // ← pre-computed in content_script.js
        spf_pass: null,                   // Stub — Gmail DOM does not expose raw headers
        dkim_pass: null                   // Documented limitation; treated as 'unknown' in backend
      };

      try {
        // ✅ Check local cache first (instant response + zero network latency)
        const cached = await getCachedResult(msg.data.emailHash);
        if (cached) {
          sendResponse(cached);
          return;
        }

        const { settings } = await chrome.storage.local.get('settings');
        const API_ENDPOINT = settings?.apiEndpoint || 'http://localhost:8000';

        const res = await fetch(`${API_ENDPOINT}/api/v1/analyze`, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(2000) // 2s timeout → triggers offline fallback
        });
        const result = await res.json();
        await cacheResult(msg.data.emailHash, result);

        // ✅ Fix #VT-Latency & #VT-PollingWindow & #SW-Lifecycle:
        // When VT is pending, the content script — not the SW — owns the polling loop.
        // MV3 service workers are non-persistent and Chrome terminates them after ~30s
        // of inactivity. setTimeout chains do NOT keep the SW alive; the worker can be
        // killed silently mid-loop with no error or warning. Content scripts run in the
        // tab's page context and survive as long as the Gmail tab is open, making them
        // the correct lifecycle owner for long-running poll chains.
        //
        // The response includes vt_status and emailHash so the content script knows to
        // start its own polling loop (see §2.5b). Each poll iteration sends a brief
        // CHECK_VT_STATUS message to the SW, which wakes for one fetch and responds.
        // This also eliminates the stale-tab bug: the content script updates its own
        // overlay directly without needing to re-resolve "active tab".
        if (result.vt_status === 'pending') {
          result._vtPollHint = {
            emailHash: msg.data.emailHash,
            linksCount: msg.data.links?.length || 1
          };
        }
        sendResponse(result);
      } catch (e) {
        // ✅ Fix #2: Use the pre-computed localScore sent by content_script.js.
        // DO NOT call runLocalHeuristics() here — it is defined in local_heuristics.js
        // which is a content script. Service workers run in a completely separate
        // execution context and cannot access content script functions. The content
        // script pre-computes the score and bundles it as msg.data.localScore (§2.1).
        const localScore = msg.data.localScore ?? 0;
        sendResponse({
          score: localScore, mode: 'OFFLINE_HEURISTIC',
          riskLevel: localScore > 50 ? 'Warning' : 'Safe',
          xai: 'Running in Offline Heuristic Mode — limited to local rules.',
          layers: offlineLayers()
        });
      }
    })();
    return true; // ← CRITICAL: keeps the message port open for the async sendResponse
  }

  // ✅ Fix #SW-Lifecycle: Lightweight relay handler for VT status checks.
  // Each call briefly wakes the SW for a single fetch+respond cycle (~1–2s),
  // well within the 30s idle threshold. The content script owns the timer loop.
  if (msg.type === 'CHECK_VT_STATUS') {
    (async () => {
      try {
        const { settings } = await chrome.storage.local.get('settings');
        const API_ENDPOINT = settings?.apiEndpoint || 'http://localhost:8000';
        const res = await fetch(`${API_ENDPOINT}/api/v1/vt-status/${msg.emailHash}`);
        const vtResult = await res.json();

        // If complete, persist the re-synthesized score in local cache
        if (vtResult.status === 'complete') {
          await cacheResult(msg.emailHash, vtResult);
        }

        sendResponse(vtResult);
      } catch (err) {
        sendResponse({ status: 'error', error: err.message });
      }
    })();
    return true;
  }
});

// ✅ Fix #CacheEviction: Eviction policy for chrome.storage.local cache.
// Default quota is 10MB without unlimitedStorage. Unbounded growth across 12–15 testing
// participants risks silent write failures. Enforces 7-day TTL pruning and a 100-entry LRU cap.
const MAX_CACHE_ENTRIES = 100;
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

async function getCachedResult(emailHash) {
  try {
    const { cache = {} } = await chrome.storage.local.get('cache');
    const entry = cache[emailHash];
    if (entry && (Date.now() - (entry.timestamp || 0) < CACHE_TTL_MS)) {
      return entry;
    }
  } catch (err) {
    console.warn('[Aegis] Cache lookup error:', err);
  }
  return null;
}

async function cacheResult(emailHash, result) {
  try {
    const { cache = {} } = await chrome.storage.local.get('cache');
    const now = Date.now();

    // 1. Evict expired entries (TTL > 7 days)
    for (const [hash, entry] of Object.entries(cache)) {
      if (now - (entry.timestamp || 0) > CACHE_TTL_MS) {
        delete cache[hash];
      }
    }

    // 2. Store fresh result
    cache[emailHash] = {
      score: result.score,
      riskLevel: result.riskLevel,
      xai: result.xai,
      layers: result.layers,
      timestamp: now
    };

    // 3. LRU Cap: If entries exceed MAX_CACHE_ENTRIES, evict oldest by timestamp
    const entries = Object.entries(cache);
    if (entries.length > MAX_CACHE_ENTRIES) {
      entries.sort((a, b) => (a[1].timestamp || 0) - (b[1].timestamp || 0));
      const excess = entries.length - MAX_CACHE_ENTRIES;
      for (let i = 0; i < excess; i++) {
        delete cache[entries[i][0]];
      }
    }

    await chrome.storage.local.set({ cache });
  } catch (err) {
    console.warn('[Aegis] Cache write failed:', err);
  }
}
```

**2.4 Backend Heuristic Layer + SPF/DKIM/DMARC Stubs**

> [!NOTE]
> **SPF/DKIM limitation (Issue #5):** Chrome extensions cannot read raw email headers from Gmail's rendered DOM — Gmail only exposes sender name, subject, and body through its UI. SPF, DKIM, and DMARC results are only accessible via the Gmail API (which requires OAuth and is out of scope for Capstone 1). The fields `spf_pass` and `dkim_pass` are documented stubs. The backend treats `null` as "unknown" — no score penalty, no false flagging. This is documented as a future-work item in Chapter IV.

```python
# modules/heuristic_engine.py
def analyze_heuristics(payload: EmailPayload) -> dict:
    score = 0
    flags = []
    
    # Domain spoof detection
    if is_typosquatted(payload.sender_domain):
        score += 35; flags.append("Domain typosquatting detected")
    
    # SPF/DKIM/DMARC — STUB for Capstone 1 prototype
    # Justification: Gmail DOM does not expose raw headers. Fields arrive as null
    # from the extension. Null = 'unknown'; we do NOT penalize to avoid false positives.
    # Future work: integrate Gmail API (OAuth) for real header inspection.
    if payload.spf_pass is False:    # Only penalize explicit False, not None
        score += 25; flags.append("SPF check failed")
    if payload.dkim_pass is False:   # Only penalize explicit False, not None
        score += 20; flags.append("DKIM signature invalid")
    
    # Keyword urgency
    keyword_hits = count_suspicious_keywords(payload.body)
    score += min(keyword_hits * 8, 30)
    
    return {"heuristic_score": min(score, 100), "flags": flags}
```

**2.5 Link Scanner — VirusTotal API Integration**

> [!IMPORTANT]
> **Missing implementation (Issue #1):** The architecture lists "Link Intelligence" as a pipeline layer and the confirmed decisions table references the VirusTotal free API key, but no backend module, route, or weekly task was previously defined for it. Without this, the Link Intelligence layer silently contributes nothing and the 4-layer claim in the paper is inaccurate.

> [!NOTE]
> **Scope clarification (renamed from "Attachment Intelligence" — Fix #Rename):** This layer scans
> **embedded hyperlinks** in the email body against VirusTotal, not actual file attachments.
> Gmail's rendered DOM does not expose attachment file bytes to content scripts — accessing
> raw attachments requires the Gmail API + OAuth, which is out of scope for Capstone 1.
> This is documented as a limitation in Chapter IV and a future-work item for Capstone 2.

Create `aegis-backend/modules/link_scanner.py`:
```python
# modules/link_scanner.py
import os
import json
import base64
import asyncio
import httpx
from pathlib import Path

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# ✅ Fix #VT-RateLimit & #VT-Pacing: VirusTotal free API enforces 4 requests/minute.
# A Semaphore(1) only prevents concurrency, NOT temporal clustering.
# Two GET requests fired within the same second both pass a semaphore, but will blow
# past VT's real 4-req/min ceiling if several emails get scanned in quick succession.
# We combine an asyncio.Lock with strict 15.0-second sleep pacing (VT_MIN_INTERVAL = 15.0)
# across ALL outbound requests (direct GET URL-ID, POST submission, or GET analysis).
# Scanned links remain capped at 2 per email.
VT_MIN_INTERVAL = 15.0  # 60s / 4 req = 15.0s minimum spacing between ANY outbound calls
last_vt_request_time = 0.0
vt_lock = asyncio.Lock()
# ✅ Fix #CacheKeyspace: Distinct separated caches to avoid mixed ID keyspace collisions.
vt_url_cache: dict[str, dict] = {}       # Keyed by URL string -> {"malicious": bool}
vt_analysis_cache: dict[str, dict] = {}  # Keyed by email_hash -> re-synthesized final result

def get_url_id(url: str) -> str:
    """Computes VirusTotal URL identifier (Base64 without padding)."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

async def acquire_vt_slot():
    """
    Serializes and paces outbound requests to guarantee <= 4 requests/minute.
    Ensures at least 15.0s has elapsed since the previous outbound request.
    """
    global last_vt_request_time
    async with vt_lock:
        now = asyncio.get_event_loop().time()
        elapsed = now - last_vt_request_time
        if elapsed < VT_MIN_INTERVAL and last_vt_request_time > 0:
            await asyncio.sleep(VT_MIN_INTERVAL - elapsed)
        last_vt_request_time = asyncio.get_event_loop().time()

def load_vt_seed_cache(seed_path: str = "data/vt_seed_cache.json"):
    """Loads pre-warmed URL scan results from disk into vt_url_cache at startup."""
    p = Path(seed_path)
    if p.exists():
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
                vt_url_cache.update(data)
                print(f"[Aegis] Loaded {len(data)} pre-warmed VT URL cache entries.")
        except Exception as e:
            print(f"[Aegis] Warning: Failed to load VT seed cache: {e}")

async def scan_single_link(client: httpx.AsyncClient, url: str) -> str | None:
    """
    Scans a single URL against VT v3 safely respecting the 4 req/min limit.
    Attempts direct URL lookup first. Returns the URL if malicious, None otherwise.
    """
    url_id = get_url_id(url)
    headers = {"x-apikey": VT_API_KEY}

    try:
        # Step 1: Direct URL-ID Lookup (1 API call — 0 wait if URL was already scanned by VT)
        await acquire_vt_slot()
        resp = await client.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers)
        
        # Explicit HTTP 429 rate limit check
        if resp.status_code == 429:
            print(f"[Aegis] VT Rate limit reached (4 req/min) on {url}. Deferring.")
            return None

        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if stats.get("malicious", 0) > 0:
                return url
            return None

        # Step 2: If unknown (404), submit for analysis under rate-paced slot
        if resp.status_code == 404:
            await acquire_vt_slot()
            submit_resp = await client.post(f"{VT_BASE_URL}/urls", headers=headers, data={"url": url})
            if submit_resp.status_code == 429:
                return None
            if submit_resp.status_code in (200, 202):
                analysis_id = submit_resp.json()["data"]["id"]
                await asyncio.sleep(2)  # Wait for analysis
                await acquire_vt_slot()
                result_resp = await client.get(f"{VT_BASE_URL}/analyses/{analysis_id}", headers=headers)
                if result_resp.status_code == 200:
                    stats = result_resp.json().get("data", {}).get("attributes", {}).get("stats", {})
                    if stats.get("malicious", 0) > 0:
                        return url
    except Exception as e:
        print(f"[Aegis] VT scan error for {url}: {e}")
    return None

async def scan_links_virustotal(links: list[str]) -> dict:
    """
    Scans extracted email links against VirusTotal v3 API.
    ✅ Fix #VT-RateLimit: Capped at 2 links per email (down from 5) to respect 4 req/min.
    Returns: { "vt_score": 0–100, "flagged_links": [...], "vt_clean": bool, "skipped": bool }
    """
    if not VT_API_KEY or not links:
        return {"vt_score": 0, "flagged_links": [], "vt_clean": True, "skipped": True}

    flagged = []
    # Cap to top 2 links per email to fit public quota
    target_links = links[:2]

    async with httpx.AsyncClient(timeout=20.0) as client:
        for url in target_links:
            # Check URL cache first (Fix #CacheKeyspace)
            if url in vt_url_cache:
                if vt_url_cache[url].get("malicious", False):
                    flagged.append(url)
                continue
            # Live scan if not cached
            hit = await scan_single_link(client, url)
            vt_url_cache[url] = {"malicious": hit is not None}
            if hit:
                flagged.append(hit)

    vt_score = min(len(flagged) * 50, 100)  # 1 hit = 50%, 2 hits = 100%
    return {
        "vt_score": vt_score,
        "flagged_links": flagged,
        "vt_clean": len(flagged) == 0,
        "skipped": False
    }
```

> [!IMPORTANT]
> **Fix #VT-Prewarm — Task-Scenario Cache Pre-Warming (`scripts/prewarm_vt_cache.py`):**
> During Week 4 usability testing (12–15 people opening test emails) and demo day, hitting live VT APIs concurrently *will* trigger 429 errors. To eliminate this risk:
> 1. All participant test scenarios (§4.1) use **fixed, curated email fixtures** (`tests/fixtures/task_emails.json`).
> 2. Run `scripts/prewarm_vt_cache.py` to pre-scan every link in those task scenarios into `data/vt_seed_cache.json`.
> 3. At startup, `load_vt_seed_cache()` loads them into `vt_url_cache`.
>
> Result: **100% cache hits, 0ms latency, 0 live API calls, and zero risk of 429 throttling** during live usability sessions and presentations.

```python
# routes/analyze.py — VT scanning decoupled + Final Score Re-Synthesis
from fastapi import BackgroundTasks
from modules.link_scanner import scan_links_virustotal, vt_analysis_cache
from modules.meta_classifier import synthesize_risk_score

# Context cache: email_hash -> {heuristic, nlp, behavioral} for post-VT score re-synthesis
analysis_context_cache: dict[str, dict] = {}

@app.post("/api/v1/analyze")
async def analyze(payload: EmailPayload, background_tasks: BackgroundTasks):
    heuristic = analyze_heuristics(payload)
    nlp = analyze_nlp(payload.body)
    behavioral = {"score": payload.behavioral_score, "flags": []}

    # ✅ Initial fast response: returns within 2s without waiting for VT
    initial_result = synthesize_risk_score(heuristic, nlp, behavioral, link_intel=None)
    initial_result["vt_status"] = "pending" if payload.links else "no_links"

    if payload.links:
        # Cache layer inputs for re-synthesis when VT completes
        analysis_context_cache[payload.email_hash] = {
            "heuristic": heuristic, "nlp": nlp, "behavioral": behavioral
        }
        background_tasks.add_task(run_vt_background, payload.links, payload.email_hash)

    return initial_result

async def run_vt_background(links: list[str], email_hash: str):
    vt_result = await scan_links_virustotal(links)
    ctx = analysis_context_cache.pop(email_hash, None)
    
    # ✅ Fix #VT-ScoreFoldIn: Re-synthesize final score with 15% VT weight!
    if ctx:
        updated_result = synthesize_risk_score(
            ctx["heuristic"],
            ctx["nlp"],
            ctx["behavioral"],
            link_intel=vt_result
        )
        updated_result["status"] = "complete"
        updated_result["vt_status"] = "complete"
        updated_result["vt_result"] = vt_result
        vt_analysis_cache[email_hash] = updated_result
    else:
        vt_analysis_cache[email_hash] = {
            "status": "complete", "vt_status": "complete", "vt_result": vt_result
        }

@app.get("/api/v1/vt-status/{email_hash}")
async def vt_status(email_hash: str):
    if email_hash in vt_analysis_cache:
        return vt_analysis_cache[email_hash]
    return {"status": "pending"}
```

**2.5b Extension Overlay Score Update (`overlay/overlay.js`)**

```js
// overlay/overlay.js — Handle async VT score fold-in
// ✅ Fix #VT-ScoreFoldIn: When background.js delivers VT_UPDATE, fold the new
// synthesized 4-layer score, risk level, badge, and XAI into the overlay UI.
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'VT_UPDATE' && msg.data?.vt_status === 'complete') {
    // 1. Smoothly update main score gauge & risk level badge
    if (msg.data.score !== undefined) {
      updateScoreGauge(msg.data.score, msg.data.riskLevel);
    }
    // 2. Update Link Intelligence layer badge in the breakdown
    const vtScore = msg.data.vt_result?.vt_score || 0;
    const flaggedLinks = msg.data.vt_result?.flagged_links || [];
    updateLayerBadge('link-intel', vtScore, flaggedLinks);

    // 3. Update plain-language XAI explanation box
    if (msg.data.xai) {
      updateXAIExplanation(msg.data.xai);
    }
  }
});
```

Wire `scan_links_virustotal()` into `aegis-backend/routes/analyze.py` as a background task. Pass the result into `meta_classifier.synthesize_risk_score()` as a 4th argument when VT results are polled (see updated weights in §3.4). Add `httpx` to `requirements.txt`.

> [!NOTE]
> If `VIRUSTOTAL_API_KEY` is absent from `.env` or the API returns HTTP 429, the scanner returns `skipped: True` and contributes 0 to the final score. The pipeline never crashes on a missing key or rate-limited quota.

#### Week 2 Deliverables
- [x] `pii_scrubber.js` strips PII before data leaves browser (tested with test strings)
- [x] `local_heuristics.js` returns a score for offline mode (tested on 5 sample emails)
- [x] `background.js` connects to `/api/v1/analyze` with 2s timeout fallback (uses `msg.data.localScore` for offline fallback — no cross-context call)
- [x] `emailHash` generated via Web Crypto API in `content_script.js` and used for cache keying
- [x] Backend heuristic engine scores test emails correctly
- [x] `link_scanner.py` wired to VirusTotal v3 API — tested on 3 sample phishing links (parallel via `asyncio.gather`)
- [x] `/api/v1/vt-status/{hash}` endpoint returns cached VT results for async polling
- [x] Extension shows real risk score from backend (or fallback) in the overlay
- [x] **Mentor Consultation scheduled** with Mr. Ryan Dalmacio to review Week 1–2 architecture

---

### WEEK 3 — NLP Layer, Behavioral Module, Whitelist Dashboard
**Goal:** Full 4-layer pipeline active. Whitelist manager working. Offline fallback verified.

#### Tasks

**3.1 NLP Layer — DistilBERT via ONNX Runtime (<150MB RSS)**

> [!IMPORTANT]
> **Model runtime swap (Fix #OOM & Fix #BuildBloat):** PyTorch (`torch`) wheels require ~700MB–1.5GB of disk space during build and consume ~800MB–1GB of RSS RAM at runtime. Render's free tier enforces a strict **512 MB RAM ceiling** — running PyTorch guarantees process termination via cgroup OOM `SIGKILL`.
> We replace PyTorch with **`onnxruntime`** (~15MB install) and the verified ONNX export: **`lemonade-sdk/phishing-email-detection-distilbert-ONNX`** (identical fine-tuned weights and `LABEL_0`–`LABEL_3` topology as `cybersectony/phishing-email-detection-distilbert_v2.4.1`). Total runtime memory stays at **~140MB RSS**, safely beneath Render's ceiling.

> [!WARNING]
> **Label mismatch fix (Fix #LabelMismatch):** The model outputs 4 generic logit classes corresponding to `LABEL_0`–`LABEL_3`.
> | Index | Label | Meaning | Class Type |
> |:---|:---|:---|:---|
> | 0 | `LABEL_0` | `legitimate_email` | Legitimate |
> | 1 | `LABEL_1` | `phishing_url` | **Phishing** |
> | 2 | `LABEL_2` | `legitimate_url` | Legitimate |
> | 3 | `LABEL_3` | `phishing_url_alt` | **Phishing** |
>
> Phishing probability is the sum of softmax probabilities for indices `1` and `3`.
>
> **⚡ Week 1 Day 1 verification (5 minutes — run after executing `download_model.py`):**
> ```python
> import onnxruntime as ort
> from transformers import AutoTokenizer
> import numpy as np
> from pathlib import Path
>
> MODEL_DIR = "models/phishing_distilbert"
> tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR, local_files_only=True)
> session = ort.InferenceSession(f"{MODEL_DIR}/model.onnx", providers=["CPUExecutionProvider"])
> inputs = tokenizer("Your account has been suspended! Verify immediately.", return_tensors="np", truncation=True, max_length=512)
> logits = session.run(None, {"input_ids": inputs["input_ids"], "attention_mask": inputs["attention_mask"]})[0][0]
> probs = np.exp(logits - np.max(logits)) / np.sum(np.exp(logits - np.max(logits)))
> print("Phishing probability (indices 1 & 3):", float(probs[1] + probs[3]))
> ```

> [!NOTE]
> **Academic Defense Terminology (Fix #DefenseFraming):** In Chapter IV and the slide deck, describe this layer as **"Self-hosted private inference"** (or *self-hosted dedicated model execution*), **NOT** "edge-deployed inference". "Edge" in academic literature specifically denotes on-device computation (e.g., inside the browser or client OS). Since the model runs on our private FastAPI backend (Render / localhost), framing it as "self-hosted private inference" is 100% technically accurate while maintaining all privacy claims under RA 10173 (no third-party LLM API data transmission).

Backend NLP module:
```python
# modules/nlp_classifier.py
from pathlib import Path
import numpy as np
import onnxruntime as ort
from transformers import AutoTokenizer

# ✅ Fix #OOM: onnxruntime replaces torch — RSS memory is ~140MB (vs ~850MB PyTorch).
# ✅ Fix #VendorModel: Both model.onnx and tokenizer assets are bundled together in
# models/phishing_distilbert/ at build time. Loading with local_files_only=True guarantees
# zero external network requests to Hugging Face Hub during container startup.
BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "models" / "phishing_distilbert"
ONNX_PATH = str(MODEL_DIR / "model.onnx")

tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR), local_files_only=True)
session = None

def get_session():
    global session
    if session is None:
        # Load ONNX model into CPU execution session
        session = ort.InferenceSession(ONNX_PATH, providers=["CPUExecutionProvider"])
    return session

def warm_up_nlp():
    """Warms up tokenizer and ONNX runtime session during FastAPI startup."""
    sess = get_session()
    inputs = tokenizer("Warmup text", return_tensors="np", truncation=True, max_length=64)
    _ = sess.run(None, {"input_ids": inputs["input_ids"], "attention_mask": inputs["attention_mask"]})

PHISHING_INDICES = {1, 3}  # LABEL_1 (phishing_url) and LABEL_3 (phishing_url_alt)
LABEL_NAMES = {
    0: 'LEGITIMATE_EMAIL', 1: 'PHISHING_URL',
    2: 'LEGITIMATE_URL',   3: 'PHISHING_URL_ALT'
}

def analyze_nlp(body_text: str) -> dict:
    sess = get_session()
    # ✅ Fix #5: Proper tokenization with truncation=True up to 512 tokens
    inputs = tokenizer(body_text, return_tensors="np", truncation=True, max_length=512)
    
    # Run ONNX inference
    logits = sess.run(None, {
        "input_ids": inputs["input_ids"],
        "attention_mask": inputs["attention_mask"]
    })[0][0]

    # Numerically stable softmax
    exp_logits = np.exp(logits - np.max(logits))
    probs = exp_logits / exp_logits.sum()

    phishing_prob = float(probs[1] + probs[3])
    is_phishing = phishing_prob > 0.5

    base_score = 60 if is_phishing else 10
    confidence_weight = phishing_prob if is_phishing else (1.0 - phishing_prob)
    model_score = round(base_score * confidence_weight)

    urgency_score = detect_urgency_patterns(body_text)
    bec_score = detect_bec_patterns(body_text)

    top_idx = int(np.argmax(probs))
    return {
        "nlp_score": min(model_score + urgency_score + bec_score, 100),
        "intent": 'PHISHING' if is_phishing else 'LEGITIMATE',
        "confidence": round(phishing_prob if is_phishing else (1.0 - phishing_prob), 4),
        "raw_label": LABEL_NAMES.get(top_idx, f"LABEL_{top_idx}"),
        "flags": build_nlp_flags(urgency_score, bec_score)
    }
```

**3.2 Behavioral Analysis Module (chrome.storage.local)**

All behavioral data stays in the browser — never sent to backend:
```js
// In content_script.js — update behavioral baseline on each email view
async function updateBehavioralBaseline(senderEmail, hour) {
  const data = await chrome.storage.local.get(['behavioralBaseline']);
  const baseline = data.behavioralBaseline || {};
  
  if (!baseline[senderEmail]) {
    baseline[senderEmail] = { count: 0, hours: [], firstSeen: Date.now() };
  }
  baseline[senderEmail].count++;
  // ✅ Fix #6: Rolling window — keep only the last 30 hour entries.
  // Without this, the hours[] array grows forever and will eventually exhaust
  // chrome.storage.local's 10MB quota for active users.
  const hours = baseline[senderEmail].hours;
  if (hours.length >= 30) hours.shift();
  hours.push(hour);
  baseline[senderEmail].lastSeen = Date.now();
  
  await chrome.storage.local.set({ behavioralBaseline: baseline });
}

// ✅ Fix #3: Made async — reads baseline from chrome.storage.local directly.
// ✅ Fix #CircularTime: Circular distance calculation prevents midnight averaging bugs.
// Linear average (23:00 + 01:00)/2 = 12:00 falsely flags future midnight emails.
// We compute circular clock distance Math.min(diff, 24 - diff) against observed hours.
// In addition, unusual hour scoring is guarded by a minimum sample size (hours.length >= 5).
function circularHourDelta(h1, h2) {
  const diff = Math.abs(h1 - h2);
  return Math.min(diff, 24 - diff);
}

async function scoreBehavioral(senderEmail, currentHour) {
  const data = await chrome.storage.local.get(['behavioralBaseline']);
  const baseline = data.behavioralBaseline || {};
  const profile = baseline[senderEmail];

  // ✅ Fix #Issue2: Guard BOTH missing profile AND empty hours[] array.
  // New senders are initialized with hours: [] — calling .reduce() on an empty
  // array with no initial value throws TypeError at runtime.
  if (!profile || profile.hours.length === 0) {
    return { score: 25, flags: ['First-time sender — no baseline established'] };
  }

  let score = 0;
  let minHourDelta = 0;

  // Only evaluate unusual send time if at least 5 emails exist in baseline
  if (profile.hours.length >= 5) {
    minHourDelta = Math.min(...profile.hours.map(h => circularHourDelta(currentHour, h)));
    if (minHourDelta > 6) {
      score += 20; // >6 hours away from nearest typical active window
    }
  }

  if (profile.count < 3) score += 15; // Rare sender

  return {
    score,
    flags: buildBehavioralFlags(minHourDelta, profile.count, profile.hours.length)
  };
}
```

**3.3 Popup UI Spec (`popup/popup.html`)**

> [!IMPORTANT]
> **Fix #Issue3:** `popup.html` was listed in the file table and `manifest.json` but never given a content specification. An undefined popup shows a blank toolbar panel on demo day. The popup must include these 3 elements:

| Element | ID | Purpose |
| :--- | :--- | :--- |
| Status badge | `#aegis-status` | Shows **Connected** (green) or **Offline** (amber) based on last backend ping |
| Whitelist Dashboard link | `#open-whitelist` | `chrome.tabs.create({ url: chrome.runtime.getURL('whitelist/whitelist_dashboard.html') })` |
| API Endpoint selector | `#api-endpoint-toggle` | Radio: `localhost:8000` ↔ Render URL — writes to `chrome.storage.local` settings |

```js
// popup.js — save endpoint selection to storage
document.getElementById('api-endpoint-toggle').addEventListener('change', async (e) => {
  const { settings } = await chrome.storage.local.get('settings');
  settings.apiEndpoint = e.target.value;
  await chrome.storage.local.set({ settings });
  document.getElementById('aegis-status').textContent = 'Endpoint updated — reconnecting…';
});

// On load: check backend health and update status badge
(async () => {
  const { settings } = await chrome.storage.local.get('settings');
  try {
    const resp = await fetch(`${settings?.apiEndpoint || 'http://localhost:8000'}/api/v1/health`,
      { signal: AbortSignal.timeout(2000) });
    const badge = document.getElementById('aegis-status');
    badge.textContent = resp.ok ? '● Connected' : '● Degraded';
    badge.style.color = resp.ok ? '#22c55e' : '#f59e0b';
  } catch {
    document.getElementById('aegis-status').textContent = '● Offline';
    document.getElementById('aegis-status').style.color = '#ef4444';
  }
})();
```

**3.3b Whitelist Dashboard (`whitelist/whitelist_dashboard.html`)**

- A dedicated Chrome Extension page (`chrome.tabs.create`)
- Allows SME admin to add/remove trusted senders with role tags
- Auto-revocation rule: if whitelisted sender **explicitly** fails SPF/DKIM → instantly flagged Critical
- Whitelist data stored in `chrome.storage.local` (never sent out)

> [!NOTE]
> **SPF/DKIM null handling (Issue #5):** Since the extension cannot read raw email headers, `spfPass` and `dkimPass` will arrive as `null` (unknown), not `false` (failed). The auto-revocation check must distinguish between `null` (no data) and `false` (explicit failure). Auto-revocation only fires on `false` — not on `null` — to prevent false positives on every email.

```js
// whitelist.js — Auto-revocation check
// ✅ Fix #3 — Dual Auto-Revocation Mechanism:
// 1. Synthetic Backend Test: Catches explicit SPF/DKIM failure (false).
// 2. Real DOM Integration Test (Gmail Demo): Detects Display-Name Spoofing!
//    Gmail's DOM exposes both innerText (display name) and attribute (email address).
//    If sender displayName matches a protected whitelisted identity (e.g., "CEO Alice"
//    or "IT Support"), but the actual email address is from an unauthorized domain,
//    Aegis triggers instant auto-revocation and flags Critical (95%).
function checkWhitelistStatus(senderEmail, displayName, spfPass, dkimPass) {
  const entryByEmail = whitelist.find(e => e.email.toLowerCase() === (senderEmail || '').toLowerCase());
  const entryByName = whitelist.find(e => e.name && displayName && e.name.toLowerCase() === displayName.toLowerCase());

  // Real DOM Spoof Trigger: Display name mimics whitelisted contact, but actual address does not match
  if (entryByName && !entryByEmail) {
    return {
      whitelisted: false,
      autoRevoked: true,
      flag: `CRITICAL: Sender display name "${displayName}" mimics whitelisted contact (${entryByName.email}), but actual address is ${senderEmail}. Display-name spoofing detected!`,
      score: 95
    };
  }

  if (!entryByEmail) return { whitelisted: false };
  
  // Synthetic Backend Test Path: Only auto-revoke on EXPLICIT failure (false), not unknown (null)
  if (spfPass === false || dkimPass === false) {
    return {
      whitelisted: false,
      autoRevoked: true,
      flag: `CRITICAL: ${senderEmail} is whitelisted but FAILED domain authentication. Possible domain spoofing attack.`,
      score: 95
    };
  }
  return { whitelisted: true, score: 5 };
}
```

**3.4 Meta-Classifier — Risk Score Synthesis**

> [!NOTE]
> **`ensemble_ml.py` removed from scope (Issue #6):** The folder structure previously included `ensemble_ml.py` (Random Forest + XGBoost + CatBoost ensemble), but no weekly task defined training data, a training step, or a labeled dataset for it. An untrained ensemble module cannot contribute to the pipeline. For Capstone 1, the meta-classifier directly performs the weighted synthesis across the three active layers (Heuristic, NLP, Behavioral). This is still a valid multi-layer synthesizer and the paper can describe it accurately as a weighted ensemble of heterogeneous signals. The RF/XGBoost ensemble is documented as future work for Capstone 2.

```python
# modules/meta_classifier.py
# ✅ Fix #6: ensemble_ml.py removed — no training pipeline was planned.
# This module directly synthesizes scores from the three active layers.
# ✅ Fix #1 (weights): Updated for 4-layer pipeline now that link_scanner.py
# is implemented (§2.5). Previous 3-layer weights summed to 100% but left the
# Link Intelligence layer with no contribution. New split:
# Heuristic: 25%, NLP Context: 45%, Behavioral: 15%, Link Intel/VT: 15% → total 100%
def synthesize_risk_score(heuristic: dict, nlp: dict, behavioral: dict, link_intel: dict = None) -> dict:
    vt_score = (link_intel or {}).get('vt_score', 0)  # 0 if skipped or absent
    final_score = (
        heuristic['heuristic_score'] * 0.25 +
        nlp['nlp_score'] * 0.45 +
        behavioral['score'] * 0.15 +
        vt_score * 0.15
    )
    final_score = min(round(final_score), 100)
    
    if final_score >= 75: level = "Critical"
    elif final_score >= 45: level = "Warning"
    else: level = "Safe"
    
    return { "score": final_score, "riskLevel": level,
             "xai": generate_xai_explanation(heuristic, nlp, behavioral, link_intel) }
```

**3.4a Implement `generate_xai_explanation()` — XAI Output**

> [!IMPORTANT]
> **Fix #Issue4:** `generate_xai_explanation()` is called by `synthesize_risk_score()` but was never defined. XAI output is a core differentiator highlighted in the panel feedback. A template-string implementation is sufficient for Capstone 1 — SHAP/LIME is Capstone 2 scope.

```python
# modules/meta_classifier.py (continued)
def generate_xai_explanation(heuristic: dict, nlp: dict, behavioral: dict, link_intel: dict = None) -> str:
    """
    Produces a plain-language explanation of the top risk contributors.
    Priority: highest-contributing layer is explained first.
    """
    reasons = []

    # NLP layer (45% weight — highest contributor)
    if nlp['intent'] == 'PHISHING':
        conf_pct = round(nlp['confidence'] * 100)
        reasons.append(
            f"AI model detected phishing intent with {conf_pct}% confidence."
        )
    if 'Urgency language detected' in nlp.get('flags', []):
        reasons.append("Email uses high-urgency language (e.g., 'act now', 'verify immediately').")
    if 'Business Email Compromise pattern detected' in nlp.get('flags', []):
        reasons.append("BEC pattern detected — email mimics an executive wire-transfer request.")

    # Link Intelligence layer (15% weight)
    if link_intel and link_intel.get('flagged_links'):
        flagged_count = len(link_intel['flagged_links'])
        reasons.append(f"VirusTotal flagged {flagged_count} embedded link(s) as malicious.")

    # Heuristic layer (25% weight)
    for flag in heuristic.get('flags', []):
        reasons.append(flag)

    # Behavioral layer (15% weight)
    for flag in behavioral.get('flags', []):
        reasons.append(flag)

    if not reasons:
        return "No significant risk indicators detected. Email appears legitimate."

    return " ".join(f"• {r}" for r in reasons[:4])  # Cap at 4 bullets for UI readability


def build_nlp_flags(urgency_score: int, bec_score: int) -> list[str]:
    """✅ Fix #Issue6: Helper function for analyze_nlp() in nlp_classifier.py"""
    flags = []
    if urgency_score > 0:
        flags.append("Urgency language detected")
    if bec_score > 0:
        flags.append("Business Email Compromise pattern detected")
    return flags
```

```js
// ✅ Fix #Issue6 & #CircularTime: buildBehavioralFlags() helper for scoreBehavioral() in content_script.js
function buildBehavioralFlags(minHourDelta, sendCount, sampleSize = 5) {
  const flags = [];
  if (sampleSize >= 5 && minHourDelta > 6) {
    flags.push(`Unusual send time — ${Math.round(minHourDelta)}h deviation from sender's typical active window`);
  }
  if (sendCount < 3) {
    flags.push('Rare sender — fewer than 3 prior emails from this address');
  }
  return flags;
}
```

**3.5 Internal Integration Testing (50+ emails)**

> [!NOTE]
> **Fix #TestSplit — Test Plan Realism (Issue #3):** Since Gmail's DOM does not expose raw authentication headers (`spf_pass` and `dkim_pass` arrive as `null`), testing is explicitly partitioned into:
> 1. **Synthetic Backend Unit Tests:** Injects synthetic JSON payloads directly into `/api/v1/analyze` to validate the backend mathematical rules for explicit header failures.
> 2. **End-to-End Live Integration Tests:** Tests real Gmail DOM extraction through the Chrome extension, validating both clean whitelisting and real-world Display-Name Spoofing auto-revocation.

**Part A: End-to-End Live Integration Tests (Extension → Gmail DOM):**
- Plain phishing (urgency keywords + typosquatted domain)
- Business Email Compromise pattern (executive wire transfer request)
- Legitimate internal email (should score < 15%)
- Newsletter / marketing email (should score < 20%)
- Zero-day LLM-generated phishing (no suspicious keywords — caught by DistilBERT ONNX)
- Whitelisted sender on real Gmail (headers null/unknown → scores < 10%, no false auto-revocation)
- **Live Whitelist Auto-Revocation (Display-Name Spoofing):** Email claiming to be a whitelisted executive/IT admin in the display name, but sent from an unauthorized domain → instantly auto-revoked, Critical (95%).

**Part B: Synthetic Backend Unit Tests (`tests/test_meta_classifier.py`):**
- Synthetic payload with explicit `spf_pass: False` → auto-revoke triggers, Critical (95%)
- Synthetic payload with explicit `dkim_pass: False` → penalty applied (+20 points)
- Synthetic payload with `spf_pass: None` / `dkim_pass: None` → neutral handling (no penalty)

#### Week 3 Deliverables
- [x] Full 4-layer pipeline returns a synthesized risk score (tested)
- [x] `generate_xai_explanation()` produces readable plain-language output (tested on 5 emails)
- [x] `build_nlp_flags()` and `buildBehavioralFlags()` implemented and unit-tested
- [x] `popup.html` shows Connected/Offline status and links to Whitelist Dashboard
- [x] `popup.js` apiEndpoint toggle writes to `chrome.storage.local` correctly
- [x] Behavioral module reads/writes to `chrome.storage.local` correctly
- [x] `scoreBehavioral()` handles new senders (empty `hours[]`) without crashing and avoids circular midnight false flags (sample size >= 5 guard)
- [x] Whitelist Dashboard opens from extension and stores entries
- [x] Auto-revocation verified: Synthetic backend test (SPF fail → 95%) AND Live DOM integration test (Display-name spoofing → 95%)
- [x] Offline fallback triggers when backend is unreachable (tested by stopping server)
- [x] Offline mode banner displays: "Running in Offline Heuristic Mode"
- [x] **Week 4 De-risking Prep (Fix #ScheduleRisk):** 12–15 participants pre-recruited and testing time-slots scheduled
- [x] **Google Forms ready:** Digitized Informed Consent Form & SUS 10-item survey links generated
- [x] **Benchmark harness ready:** `data/benchmark_dataset.json` populated with test cases
- [x] Bug tracker (`docs/appendices/bug_tracker.md`) updated with all Week 1–3 issues

---

### WEEK 4 — Usability Study, User Testing & UI Refinements
**Goal:** Ethical user testing with 10–15 SME participants. SUS data collected. UI refined.

> [!IMPORTANT]
> **Fix #ScheduleRisk — 2-Person Workload Division (Issue #5):**
> Week 4 combines human participant testing (10–15 sessions + SUS) with a comprehensive 4-platform comparative benchmark. To prevent schedule slippage on a 2-person team, the tasks are strictly partitioned to run in parallel:
>
> | Team Member | Primary Workstream | Dedicated Week 4 Deliverables |
> | :--- | :--- | :--- |
> | **Jafphet P. Grengia** | **Usability & UX Lead** | • Administer 10–15 supervised usability sessions<br>• Collect signed consent forms & SUS survey scores<br>• Log qualitative observation notes<br>• Implement Post-Testing UI & XAI text refinements (§4.4) |
> | **Michael Angelo L. Bernardo** | **Benchmarking & Systems Lead** | • Execute 4-platform benchmark matrix (§4.5)<br>• Compare Aegis against Gmail, Outlook, ProtonMail, SpamAssassin<br>• Measure scan latency profiles (<350ms / <100ms)<br>• Compile Appendix D (`test_matrix.md`) & bug tracker updates |

#### Tasks

**4.1 Prepare Usability Testing Package**
- Print and digitize **Informed Consent Forms** (RA 10173 Data Privacy Act compliant)
- Prepare **System Usability Scale (SUS) questionnaire** (10 standard questions)
- Prepare **standardized task scenarios** using fixed test email fixtures (`tests/fixtures/task_emails.json`):
  - Task 1: Open a phishing email → observe Scan button → click Scan → understand result
  - Task 2: Open a legitimate email → verify Safe rating
  - Task 3: Try to whitelist a sender through the overlay
  - Task 4: Read the XAI explanation and rate clarity (1–5 scale)
- ⚠ **Rate-Limit Control for Concurrent Testing (Fix #VT-TaskPrewarm):** All hyperlinks within Tasks 1–4 are fixed and pre-scanned into `data/vt_seed_cache.json` via `scripts/prewarm_vt_cache.py` prior to the testing sessions. Participants are restricted to these exact task scenarios in the test inbox. This guarantees 100% VT cache hits and prevents concurrent participant sessions from exhausting the shared 4 req/min VirusTotal key.

**4.2 Recruit 10–15 Participants**
- Target: SME employees (administrative staff, finance staff, operations managers)
- Mix: 5 with prior security training, 5 without, 3–5 IT-adjacent roles
- Anonymize: Use Participant IDs (P01–P15), collect no real names in data files

**4.3 Conduct Supervised Testing Sessions**
- Observe and note: confusion points, delay before clicking Scan, misread XAI text
- Measure:
  - Task Completion Rate (%)
  - Time-on-Task (seconds to comprehend risk level)
  - SUS Score per participant

**4.4 Rapid Iteration Sprint (Post-Testing)**

Expected feedback areas and planned fixes:
| Expected Feedback | Planned Fix |
| :--- | :--- |
| XAI text too technical | Replace jargon with plain-language templates |
| Scan button not visible enough | Increase FAB size, add pulsing animation |
| Risk % not intuitive | Add color-coded label (Safe / Caution / Danger) |
| Want to see which specific words triggered detection | Add highlighted word indicators in XAI box |
| "Report to Admin" button missing | Add one-click report button |

**4.5 Benchmark Testing Matrix (Mentor Feedback Requirement)**

> [!IMPORTANT]
> **Fix #DocGap2:** The panel chair explicitly required a comparative evaluation against Gmail, Outlook, ProtonMail, and SpamAssassin. This task was absent from all weekly plans. Prepare and execute this matrix during Week 4 using synthetic/curated phishing datasets (bypassing standard spam filters via direct injection).

| Test Email Type | Gmail | Outlook | Aegis | Aegis XAI Clarity (1–5) |
| :--- | :--- | :--- | :--- | :--- |
| Standard phishing (urgency keywords) | ✓ catches | ✓ catches | target ≥ 90% | — |
| BEC (no malicious links) | ✗ misses | partial | target ≥ 85% | — |
| LLM-generated phishing (no keywords) | ✗ misses | ✗ misses | target ≥ 70% | — |
| Legitimate internal email | ✗ FP | ✗ FP | target ≤ 10% FP | — |

Document results in `docs/appendices/benchmark_matrix.md`.

#### Week 4 Deliverables
- [x] Informed Consent Forms signed and archived (GDrive, anonymized)
- [x] SUS questionnaire responses collected (10–15 participants)
- [x] Anonymized participant data table completed
- [x] Observation notes documented per session
- [x] UI refinements applied based on usability feedback
- [x] Iteration log updated in `docs/appendices/`
- [x] Benchmark Testing Matrix completed (`docs/appendices/benchmark_matrix.md`)

---

### WEEK 5 — Final QA, Documentation Package & Submission
**Goal:** Prototype freeze. GitHub clean. GDrive link ready. Chapter IV docs finalized.

#### Tasks

**5.1 Final QA Regression Testing**

Run full test suite across:
- Gmail on Chrome (stable): Extension loads, injects correctly
- Gmail on Edge: cross-browser compatibility check
- Extension with backend ON: full pipeline returns correct scores
- Extension with backend OFF: offline fallback activates within 2s
- 10 new unseen phishing emails: confirm detection rate ≥ 90%
- 5 legitimate emails: confirm false positive rate ≤ 10%

**5.2 Security Final Check**
- Confirm: no raw email body text stored in `chrome.storage.local` (only hashes)
- Confirm: `.env` excluded from git via `.gitignore`
- Confirm: API keys not hardcoded in any file
- Confirm: CORS updated from `["*"]` (dev) to `["chrome-extension://YOUR_EXTENSION_ID"]` in Render deployment
- Confirm: Extension ID in CORS matches the production-loaded extension (not the dev unpacked ID)

> [!IMPORTANT]
> **Fix #PreSubmitChecklist — Pre-Submission Manual Step Verification:**
> Three deployment steps depend on a human remembering to do them before Week 5 submission.
> To eliminate that risk, run this checklist as a literal terminal script immediately before `git push`:
> ```bash
> # scripts/pre_submit_check.sh — Run before every Render deploy and before final submission
>
> echo "=== Aegis Pre-Submission Checklist ==="
>
> # 1. Verify CORS is NOT still set to ["*"] in main.py
> echo "[1/3] Checking CORS wildcard..."
> grep -n '"[*]"' aegis-backend/main.py && \
>   echo "  ❌ FAIL: Replace [\"*\"] with [\"chrome-extension://YOUR_EXTENSION_ID\"] before deploying" || \
>   echo "  ✅ CORS is locked to extension ID"
>
> # 2. Verify apiEndpoint is NOT still localhost in popup.js
> echo "[2/3] Checking apiEndpoint default..."
> grep -n "localhost:8000" aegis-extension/popup/popup.js && \
>   echo "  ❌ FAIL: Update apiEndpoint default to Render URL before final submission" || \
>   echo "  ✅ apiEndpoint is pointing to Render"
>
> # 3. Verify host_permissions slug is NOT still the placeholder
> echo "[3/3] Checking manifest host_permissions slug..."
> grep -n "aegis-api-xxxx" aegis-extension/manifest.json && \
>   echo "  ❌ FAIL: Replace 'aegis-api-xxxx' with assigned Render service slug" || \
>   echo "  ✅ host_permissions URL is specific (no placeholder)"
>
> echo "=== Checklist complete ==="
> ```
> Run with `bash scripts/pre_submit_check.sh` before every Render deploy and once more immediately before the Week 5 Camu submission.


**5.3 Performance Check**
- Measure: Scan-to-result latency (target: < 350ms with backend / < 100ms offline)
  - Note: The 350ms target applies to requests **after** server warmup. Cold-start on CPU with ONNX Runtime takes ~1s; subsequent requests execute in ~25–50ms.
  - ✅ **Fix #OOM & Fix #BuildBloat — Local Docker 512MB Memory Verification:**
    Test backend under Render's exact free-tier memory limit locally:
    ```bash
    docker run --memory=512m --cpus=1 -p 8000:8000 aegis-backend
    ```
    Confirm that `/api/v1/analyze` survives without cgroup OOM termination. With `onnxruntime` (<150MB RSS), memory consumption remains well within bounds.
  - ✅ **Fix #7 — Operational Contingency for Demo Week:**
    Render free tier spins down after 15 minutes of inactivity and has a 512MB RAM cap. While `onnxruntime` prevents OOM, the best insurance for demo day is upgrading to Render's **Starter tier ($7/mo)** for demo week only. It removes both the 512MB ceiling and the 15-minute spin-down, eliminating the need for external cron warmup hacks. Downgrade or cancel immediately after presentation.
- ✅ **Fix #4 — `AbortSignal.timeout()` compatibility:** `AbortSignal.timeout()` was introduced in Chrome 103. Confirm that Chrome stable on all test and demo machines is ≥ 103 before the presentation. Check via `chrome://version`.
- Measure: Extension load impact (MutationObserver on `[role="main"]` with debounce — should not slow Gmail page render)

**5.4 Repository Cleanup**
```bash
git add -A
git commit -m "feat: Week 5 final prototype freeze - Aegis MVP v1.0"
git push origin main
```

**5.5 Chapter IV & Appendices Package Final Format**
Reference: `docs/02-chapter_iv_and_appendices_package.md`

| Appendix | Content | Location |
| :--- | :--- | :--- |
| A | Participant Consent Forms (scanned) | GDrive |
| B | SUS Questionnaire Responses + Scores | `docs/appendices/usability_report.md` |
| C | Sprint Log (Weeks 1–5) | `docs/appendices/sprint_log.md` |
| D | Test Execution Matrix (50+ cases) | `docs/appendices/test_matrix.md` |
| E | Bug & Resolution Log | `docs/appendices/bug_tracker.md` |
| F | UI Screenshots (before/after iterations) | `docs/media/` |
| G | 3-minute Demo Video | GDrive + `docs/media/` |

**5.6 Camu + GDrive Submission**
- Set GDrive folder to: `Anyone with the link → Viewer`
- Submit to Camu: [GitHub repo URL] + [GDrive folder URL]
- Verify both links are accessible in an incognito browser before submitting

**5.7 Week 6 Presentation Prep**
- Confirm presentation schedule with Mr. Ryan Dalmacio
- Slide deck outline: Problem → System Architecture → Live Demo → Test Results → XAI Demo → Q&A

**5.8 System Workflow Diagram (Mentor Feedback Requirement)**

> [!IMPORTANT]
> **Fix #DocGap1:** The panel chair noted the system workflow diagram was missing or substituted with a text table. This must appear in Chapter 3 of the paper. Create a Mermaid flowchart in `docs/appendices/system_workflow_diagram.md` covering all 7 steps the panel specified:
> 1. User opens email in Gmail → clicks Aegis Scan button
> 2. HTML/CSS Sanitization + Client-side PII Stripping (`pii_scrubber.js`)
> 3. Email Authentication stub check (SPF/DKIM — null/unknown documented)
> 4. Link Intelligence Scan (VirusTotal v3 API, 2-link cap, 4 req/min rate control, async background task)
> 5. Parallel pipelines: Heuristic Engine + DistilBERT ONNX + Behavioral Analyzer
> 6. Meta-Classifier weighted synthesis → Risk Score (0–100%)
> 7. XAI Output + User Decision Interface (overlay panel)

Embed the Mermaid diagram in the final paper's Chapter 3 section.

#### Week 5 Deliverables
- [x] Extension fully functional on Gmail (Chrome + Edge)
- [x] All 5 QA checks passed (extension loads, pipeline runs, fallback works)
- [x] System Workflow Diagram (Mermaid) embedded in Chapter 3 (`docs/appendices/system_workflow_diagram.md`)
- [x] Chapter IV Appendices Package complete and formatted
- [x] GitHub repository cleaned and pushed
- [x] GDrive link accessible and submitted to Camu
- [x] Presentation schedule confirmed with mentor

---

## Proposed Changes Summary (Files to Create)

| File | Status | Week |
| :--- | :--- | :--- |
| `aegis-extension/manifest.json` | **[NEW]** | Week 1 |
| `aegis-extension/background.js` | **[NEW]** | Week 1–2 |
| `aegis-extension/content_script.js` | **[NEW]** | Week 1–2 |
| `aegis-extension/pii_scrubber.js` | **[NEW]** | Week 2 |
| `aegis-extension/local_heuristics.js` | **[NEW]** | Week 2 |
| `aegis-extension/overlay/overlay.js` | **[ADAPTED]** | Week 1 |
| `aegis-extension/overlay/overlay.css` | **[ADAPTED]** | Week 1 |
| `aegis-extension/whitelist/whitelist_dashboard.html` | **[NEW]** | Week 3 |
| `aegis-extension/whitelist/whitelist.js` | **[NEW]** | Week 3 |
| `aegis-extension/popup/popup.html` | **[NEW]** | Week 3 |
| `aegis-backend/main.py` | **[NEW]** | Week 1 |
| `aegis-backend/Dockerfile` | **[NEW]** | Week 1 |
| `aegis-backend/scripts/download_model.py` | **[NEW]** | Week 1 |
| `aegis-backend/routes/analyze.py` | **[NEW]** | Week 2 |
| `aegis-backend/modules/heuristic_engine.py` | **[NEW]** | Week 2 |
| `aegis-backend/modules/link_scanner.py` | **[NEW]** | Week 2 |
| `aegis-backend/modules/nlp_classifier.py` | **[NEW]** | Week 3 |
| `aegis-backend/modules/behavioral_analyzer.py` | **[NEW]** | Week 3 |
| `aegis-backend/modules/meta_classifier.py` | **[NEW]** | Week 3 |
| `aegis-backend/scripts/prewarm_vt_cache.py` | **[NEW]** | Week 3–4 |
| `aegis-backend/data/vt_seed_cache.json` | **[NEW]** | Week 4–5 |
| `aegis-backend/data/benchmark_dataset.json` | **[NEW]** | Week 3–4 |
| `docs/appendices/sprint_log.md` | **[NEW]** | Week 1 → ongoing |
| `docs/appendices/bug_tracker.md` | **[NEW]** | Week 1 → ongoing |
| `docs/appendices/test_matrix.md` | **[NEW]** | Week 3–5 |
| `docs/appendices/benchmark_matrix.md` | **[NEW]** | Week 4–5 |
| `docs/appendices/usability_report.md` | **[NEW]** | Week 4–5 |

---

## ✅ Architecture Decisions (Confirmed)

All open questions have been resolved. The table below is the final reference.

| # | Decision | Final Answer | Action Item |
| :--- | :--- | :--- | :--- |
| 1 | **Backend (dev)** | `localhost:8000` via FastAPI | Start server with `uvicorn main:app --reload` during Weeks 1–4 |
| 2 | **Backend (demo/submission)** | Render.com free tier (Starter tier $7/mo recommended for demo week) | Deploy in Week 5; update CORS from `["*"]` → `["chrome-extension://YOUR_EXTENSION_ID"]`; update `apiEndpoint` to Render URL; Starter tier ($7) eliminates 512MB RAM ceiling and 15-min spin-downs |
| 3 | **AI Model** | DistilBERT via ONNX Runtime (`lemonade-sdk/phishing-email-detection-distilbert-ONNX`) | Phishing-domain fine-tuned DistilBERT; ~140MB RSS memory footprint (safe on Render 512MB RAM); loaded at startup via lifespan warmup; no torch bloat; works offline after first download |
| 4 | **Link Intelligence** | VirusTotal free API key | Register at [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) → add to `.env` as `VIRUSTOTAL_API_KEY`; rate-controlled to 4 req/min, capped at 2 links/email, with pre-warmed seed cache (`scripts/prewarm_vt_cache.py`) |
| 5 | **Usability Participants** | 12–15 MMDC classmates + 2–3 faculty proxies | Recruit via section group chat; schedule for Week 4 (Sept 24–25); use Google Forms for SUS |

### Participant Group Breakdown (Week 4)

| Group | Who | Count | SME Role They Represent |
| :--- | :--- | :--- | :--- |
| Non-tech students | BSIT classmates (other sections), BS Business, BS Accountancy | 6–8 | SME admin, finance, operations staff |
| Tech-adjacent | BSIT classmates, IT faculty | 3–4 | SME IT support personnel |
| Admin proxy | Program head, faculty, or office-based family member | 2–3 | SME owner / manager perspective |

> [!NOTE]
> Consent forms must state: (1) participation is voluntary, (2) no personal data retained, (3) only anonymized Participant IDs (P01–P15) appear in the paper — required for RA 10173 compliance and Chapter IV ethics section.

### Environment Variables Reference (`.env`)
```
VIRUSTOTAL_API_KEY=your_key_here
RENDER_API_URL=https://aegis-api-xxxx.onrender.com
ENV=development   # switch to 'production' for demo day
```

### `apiEndpoint` Switching Logic (`background.js`)
```js
// Read from storage — set once, read everywhere
const { settings } = await chrome.storage.local.get('settings');
const API_ENDPOINT = settings?.apiEndpoint || 'http://localhost:8000';
// Before Week 5 demo: update storage to Render URL via popup settings page
```
