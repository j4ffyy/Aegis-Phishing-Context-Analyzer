# Aegis Chrome Extension — Complete Build Implementation Plan

> **Project:** AI-Powered Phishing Context Analyzer for Small and Medium Enterprises
> **Team:** Jafphet P. Grengia & Michael Angelo L. Bernardo
> **Adviser:** Mr. Ryan Dalmacio
> **Current Status:** Aegis_Prototype (demo sim) exists — needs to evolve into a real Chrome Extension MV3 package.
> **Deployment:** localhost:8000 (dev) → Render.com free tier (demo day)
> **AI Model:** Local DistilBERT via `pip install transformers` — no API key required
> **Attachment Intel:** VirusTotal free API key (500 req/day)
> **Participants:** 12–15 MMDC classmates + faculty proxies (Week 4)

---

## ✅ Confirmed Architecture Decisions

These decisions are **locked in** and reflected throughout all weekly tasks below.

| Decision | Choice | Rationale |
| :--- | :--- | :--- |
| **Backend hosting (dev)** | `localhost:8000` (FastAPI) | Zero latency, no internet dependency during Weeks 1–4 |
| **Backend hosting (demo day)** | [Render.com](https://render.com) free tier — persistent URL | Panelists can access without running your laptop; 750 hrs/month free |
| **AI model** | **Local DistilBERT** (`pip install transformers`) — no API key | Works fully offline, no rate limits, privacy-preserving, cites as "edge-deployed inference" in Chapter IV |
| **Attachment Intel** | **VirusTotal free API key** — register at virustotal.com | 500 req/day, free forever — more than sufficient for demos and usability testing |
| **Participants (Week 4)** | **12–15 MMDC classmates + 2–3 faculty/admin proxies** | Academically valid representative sample; non-tech students = SME admin/finance staff; BSIT = IT support role |

> [!NOTE]
> Store all keys in `.env` (never hardcoded). The `apiEndpoint` in `chrome.storage.local` switches between `http://localhost:8000` (dev) and the Render URL (final demo). Update this in `background.js` before Week 5 submission.

---

## What We Are Building

A **Chrome Extension (Manifest V3)** that:
1. Detects when the user is reading an email in Gmail (webmail DOM injection)
2. Extracts email context (sender, body, headers, links, attachments) entirely **client-side**
3. Strips PII before any data leaves the browser
4. Runs a **4-layer analysis pipeline** (Auth → Attachment → Behavioral → NLP/ML)
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
│   ├── main.py                         ← API server entry point
│   ├── routes/
│   │   ├── analyze.py                  ← /api/v1/analyze endpoint
│   │   └── health.py                   ← /api/v1/health endpoint
│   ├── modules/
│   │   ├── heuristic_engine.py         ← Regex + SPF/DKIM heuristics
│   │   ├── nlp_classifier.py           ← DistilBERT NLP pipeline
│   │   ├── ensemble_ml.py              ← RF + XGBoost + CatBoost
│   │   ├── behavioral_analyzer.py      ← Baseline comparison logic
│   │   └── meta_classifier.py          ← XGBoost risk score synthesis
│   ├── requirements.txt
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
```json
{
  "manifest_version": 3,
  "name": "Aegis Phishing Analyzer",
  "version": "1.0.0",
  "description": "AI-Powered Phishing Context Analyzer for SMEs",
  "permissions": ["activeTab", "storage", "scripting"],
  "host_permissions": ["https://mail.google.com/*"],
  "background": { "service_worker": "background.js" },
  "content_scripts": [{
    "matches": ["https://mail.google.com/*"],
    "js": ["pii_scrubber.js", "local_heuristics.js", "content_script.js"],
    "css": ["overlay/overlay.css"],
    "run_at": "document_idle"
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
- Waits for Gmail to load an email thread using a `MutationObserver`
- Extracts: subject, sender name, sender email, email body text, embedded links, attachment names
- Injects the Aegis overlay panel and Scan FAB button into the Gmail DOM
- Does NOT send any data — just reads and injects UI

Key Gmail DOM selectors to target:
```js
// Email subject
document.querySelector('h2.hP')
// Sender name and email
document.querySelector('.gD') // name attr = email address, innerText = name
// Email body
document.querySelector('.a3s.aiL') // main body container
// Attachments
document.querySelectorAll('.aV3') // attachment names
```

**1.3 Adapt `overlay.css` and `overlay.js` from Aegis_Prototype**
- Copy `styles.css` → `overlay/overlay.css` (remove Gmail simulation styles, keep Aegis panel styles)
- Start adapting `app.js` → `overlay.js` (remove mock email data, replace with data received from `content_script.js`)

**1.4 Set up `chrome.storage.local` structure**
```js
// Storage schema
{
  "whitelist": [],          // Array of {email, role, department, addedAt}
  "cache": {},              // Hash → {score, riskLevel, xai, timestamp}
  "behavioralBaseline": {}, // senderEmail → {frequency, lastSeen, typical_hour}
  "settings": {
    "apiEndpoint": "http://localhost:8000",
    "offlineMode": false,
    "hardCapMonthlyUSD": 5.00
  }
}
```

**1.5 Backend skeleton — FastAPI**
```python
# main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["chrome-extension://*"])

@app.get("/api/v1/health")
def health(): return {"status": "ok"}

@app.post("/api/v1/analyze")
def analyze(payload: EmailPayload): ...  # Week 2
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

All PII is removed **before** any data is sent to the backend (RA 10173 compliance):
```js
function scrubPII(text) {
  return text
    .replace(/\b[A-Z][a-z]+ [A-Z][a-z]+\b/g, '[NAME]')             // Names
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/gi, '[EMAIL]') // Emails
    .replace(/\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b/g, '[PHONE]')       // Phone numbers
    .replace(/\b(?:\d[ -]*?){13,16}\b/g, '[CARD_NUMBER]')            // Credit cards
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[SSN]');                     // SSNs
}
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

`background.js` service worker:
```js
chrome.runtime.onMessage.addListener(async (msg, sender, sendResponse) => {
  if (msg.type === 'ANALYZE_EMAIL') {
    const scrubbedPayload = {
      sender: msg.data.senderEmail,
      subject: msg.data.subject,
      body: scrubPII(msg.data.body),      // PII stripped BEFORE sending
      links: msg.data.links,
      hasAttachment: msg.data.hasAttachment
    };

    try {
      const res = await fetch(`${settings.apiEndpoint}/api/v1/analyze`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(scrubbedPayload),
        signal: AbortSignal.timeout(2000) // 2s timeout → fallback
      });
      const result = await res.json();
      // Cache the result
      cacheResult(msg.data.emailHash, result);
      sendResponse(result);
    } catch (e) {
      // OFFLINE FALLBACK: use local heuristics
      const localScore = runLocalHeuristics(msg.data);
      sendResponse({
        score: localScore, mode: 'OFFLINE_HEURISTIC',
        riskLevel: localScore > 50 ? 'Warning' : 'Safe',
        xai: 'Running in Offline Heuristic Mode — limited to local rules.',
        layers: offlineLayers()
      });
    }
  }
});
```

**2.4 Backend Heuristic Layer + SPF/DKIM/DMARC Stubs**
```python
# modules/heuristic_engine.py
def analyze_heuristics(payload: EmailPayload) -> dict:
    score = 0
    flags = []
    
    # Domain spoof detection
    if is_typosquatted(payload.sender_domain):
        score += 35; flags.append("Domain typosquatting detected")
    
    # SPF/DKIM/DMARC (stub — reads from payload header data or simulated)
    if not payload.spf_pass:
        score += 25; flags.append("SPF check failed")
    if not payload.dkim_pass:
        score += 20; flags.append("DKIM signature invalid")
    
    # Keyword urgency
    keyword_hits = count_suspicious_keywords(payload.body)
    score += min(keyword_hits * 8, 30)
    
    return {"heuristic_score": min(score, 100), "flags": flags}
```

#### Week 2 Deliverables
- [x] `pii_scrubber.js` strips PII before data leaves browser (tested with test strings)
- [x] `local_heuristics.js` returns a score for offline mode (tested on 5 sample emails)
- [x] `background.js` connects to `/api/v1/analyze` with 2s timeout fallback
- [x] Backend heuristic engine scores test emails correctly
- [x] Extension shows real risk score from backend (or fallback) in the overlay
- [x] **Mentor Consultation scheduled** with Mr. Ryan Dalmacio to review Week 1–2 architecture

---

### WEEK 3 — NLP Layer, Behavioral Module, Whitelist Dashboard
**Goal:** Full 4-layer pipeline active. Whitelist manager working. Offline fallback verified.

#### Tasks

**3.1 NLP Layer — DistilBERT via HuggingFace**

Backend NLP module:
```python
# modules/nlp_classifier.py
from transformers import pipeline

# Load once at startup (not per-request)
classifier = pipeline("text-classification",
    model="distilbert-base-uncased-finetuned-sst-2-english")
# In production: swap for a phishing-fine-tuned model

def analyze_nlp(body_text: str) -> dict:
    result = classifier(body_text[:512])[0]  # DistilBERT max input
    urgency_score = detect_urgency_patterns(body_text)
    bec_score = detect_bec_patterns(body_text)
    return {
        "nlp_score": urgency_score + bec_score,
        "intent": result['label'],
        "confidence": result['score'],
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
  baseline[senderEmail].hours.push(hour);
  baseline[senderEmail].lastSeen = Date.now();
  
  await chrome.storage.local.set({ behavioralBaseline: baseline });
}

function scoreBehavioral(senderEmail, currentHour) {
  const profile = baseline[senderEmail];
  if (!profile) return { score: 25, flag: 'First-time sender' };
  
  const avgHour = profile.hours.reduce((a,b) => a+b) / profile.hours.length;
  const hourDelta = Math.abs(currentHour - avgHour);
  
  let score = 0;
  if (hourDelta > 6) score += 20; // Unusual send time
  if (profile.count < 3) score += 15; // Rare sender
  
  return { score, flags: buildBehavioralFlags(hourDelta, profile.count) };
}
```

**3.3 Whitelist Dashboard (`whitelist/whitelist_dashboard.html`)**

- A dedicated Chrome Extension page (`chrome.tabs.create`)
- Allows SME admin to add/remove trusted senders with role tags
- Auto-revocation rule: if whitelisted sender fails SPF/DKIM → instantly flagged Critical
- Whitelist data stored in `chrome.storage.local` (never sent out)

```js
// whitelist.js — Auto-revocation check
function checkWhitelistStatus(senderEmail, spfPass, dkimPass) {
  const entry = whitelist.find(e => e.email === senderEmail);
  if (!entry) return { whitelisted: false };
  
  if (!spfPass || !dkimPass) {
    // AUTO-REVOKE: whitelisted sender failed auth
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
```python
# modules/meta_classifier.py
def synthesize_risk_score(heuristic: dict, nlp: dict, behavioral: dict) -> dict:
    # Weighted combination per approved methodology
    # Auth/Heuristic: 30%, NLP Context: 50%, Behavioral: 20%
    final_score = (
        heuristic['heuristic_score'] * 0.30 +
        nlp['nlp_score'] * 0.50 +
        behavioral['score'] * 0.20
    )
    final_score = min(round(final_score), 100)
    
    if final_score >= 75: level = "Critical"
    elif final_score >= 45: level = "Warning"
    else: level = "Safe"
    
    return { "score": final_score, "riskLevel": level,
             "xai": generate_xai_explanation(heuristic, nlp, behavioral) }
```

**3.5 Internal Integration Testing (50+ emails)**

Test matrix categories:
- Plain phishing (urgency + spoofed domain)
- BEC pattern (CEO wire transfer)
- Legitimate internal email (should score < 15%)
- Newsletter/marketing (should score < 20%)
- Zero-day LLM-generated phishing (no suspicious keywords)
- Whitelisted sender with SPF pass (should score < 10%)
- Whitelisted sender with SPF fail → auto-revoke (should score > 90%)

#### Week 3 Deliverables
- [x] Full 4-layer pipeline returns a synthesized risk score (tested)
- [x] Behavioral module reads/writes to `chrome.storage.local` correctly
- [x] Whitelist Dashboard opens from extension and stores entries
- [x] Auto-revocation tested: whitelisted + SPF fail → Critical (95%)
- [x] Offline fallback triggers when backend is unreachable (tested by stopping server)
- [x] Offline mode banner displays: "Running in Offline Heuristic Mode"
- [x] Bug tracker (`docs/appendices/bug_tracker.md`) updated with all Week 1–3 issues

---

### WEEK 4 — Usability Study, User Testing & UI Refinements
**Goal:** Ethical user testing with 10–15 SME participants. SUS data collected. UI refined.

#### Tasks

**4.1 Prepare Usability Testing Package**
- Print and digitize **Informed Consent Forms** (RA 10173 Data Privacy Act compliant)
- Prepare **System Usability Scale (SUS) questionnaire** (10 standard questions)
- Prepare **task scenarios** for participants:
  - Task 1: Open a phishing email → observe Scan button → click Scan → understand result
  - Task 2: Open a legitimate email → verify Safe rating
  - Task 3: Try to whitelist a sender through the overlay
  - Task 4: Read the XAI explanation and rate clarity (1–5 scale)

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

#### Week 4 Deliverables
- [x] Informed Consent Forms signed and archived (GDrive, anonymized)
- [x] SUS questionnaire responses collected (10–15 participants)
- [x] Anonymized participant data table completed
- [x] Observation notes documented per session
- [x] UI refinements applied based on usability feedback
- [x] Iteration log updated in `docs/appendices/`

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
- Confirm: CORS restricted to extension origin only

**5.3 Performance Check**
- Measure: Scan-to-result latency (target: < 350ms with backend / < 100ms offline)
- Measure: Extension load impact (MutationObserver should not slow Gmail page render)

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

#### Week 5 Deliverables
- [x] Extension fully functional on Gmail (Chrome + Edge)
- [x] All 5 QA checks passed (extension loads, pipeline runs, fallback works)
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
| `aegis-backend/routes/analyze.py` | **[NEW]** | Week 2 |
| `aegis-backend/modules/heuristic_engine.py` | **[NEW]** | Week 2 |
| `aegis-backend/modules/nlp_classifier.py` | **[NEW]** | Week 3 |
| `aegis-backend/modules/behavioral_analyzer.py` | **[NEW]** | Week 3 |
| `aegis-backend/modules/meta_classifier.py` | **[NEW]** | Week 3 |
| `docs/appendices/sprint_log.md` | **[NEW]** | Week 1 → ongoing |
| `docs/appendices/bug_tracker.md` | **[NEW]** | Week 1 → ongoing |
| `docs/appendices/test_matrix.md` | **[NEW]** | Week 3–5 |
| `docs/appendices/usability_report.md` | **[NEW]** | Week 4–5 |

---

## ✅ Architecture Decisions (Confirmed)

All open questions have been resolved. The table below is the final reference.

| # | Decision | Final Answer | Action Item |
| :--- | :--- | :--- | :--- |
| 1 | **Backend (dev)** | `localhost:8000` via FastAPI | Start server with `uvicorn main:app --reload` during Weeks 1–4 |
| 2 | **Backend (demo/submission)** | Render.com free tier | Deploy in Week 5 before GDrive submission; update `apiEndpoint` constant |
| 3 | **AI Model** | Local DistilBERT — `pip install transformers torch` | Download model on first run; ~250MB; works offline after that |
| 4 | **Attachment Intel** | VirusTotal free API key | Register at [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) → copy key → add to `.env` as `VIRUSTOTAL_API_KEY` |
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
