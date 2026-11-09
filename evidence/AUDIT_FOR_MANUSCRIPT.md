# AEGIS Repository Audit for Manuscript Revision

**Audit Scope:** Read-only forensic audit of the AEGIS repository at HEAD (commit `0c541f531e945793df7711ac9eda14597402b5fb` or later).  
**Repository Root:** `c:\Users\jafph\Desktop\Capstone 1 - Phishing Analyzer\Aegis-Phishing-Context-Analyzer`  
**Execution Timestamp:** 2026-11-08  
**Audit Standard:** Zero fabrication, exact line numbers, exact commit hashes, zero inference.

---

## Section A: Evaluation Harness (Phase C, E-07 / E-08)

### Item 1. Behavioral Score and VirusTotal in Phase C and Ablation Runs
* **Exact Answer:**
  * **Behavioral Score:** The backend used the neutral baseline score of **15** for every evaluation sample. In the Phase C runner, `EmailPayload` was constructed without passing `behavioralScore` or `behavioral_meta`, triggering the server-side fallback default of `15`.
  * **VirusTotal:** VirusTotal network calls were **skipped** (bypassed in offline mode; mocked with `s_vt = 0` and `vt_pending = True`). Zero network requests were transmitted to the VirusTotal v3 API during these runs.
* **Proof & Citations:**
  * `tools/run_phase_c_evaluations.py:L174-L184 @ 0c541f5`:
    ```python
    payload = EmailPayload(
        senderEmail=row.get("senderEmail", ""),
        subject=subject,
        bodyText=body,
        links=links,
        attachments=attachments,
        hasAttachment=bool(attachments),
        attachmentCount=len(attachments),
        spfPass=spf_pass,
        dkimPass=dkim_pass,
    )
    ```
    *(Note: `behavioralScore` and `behavioral_meta` are omitted).*
  * `aegis-backend/routes/analyze.py:L467-L485 @ 0c541f5`:
    ```python
    def evaluate_behavioral(payload: EmailPayload) -> int:
        if payload.behavioralScore is not None:
            ...
        if payload.behavioral_meta and isinstance(payload.behavioral_meta, dict):
            ...
        return 15
    ```
  * `tools/run_phase_c_evaluations.py:L212-L225 @ 0c541f5`:
    ```python
    final_score = synthesize_composite_score(
        s_heuristic=s_h,
        s_nlp=s_nlp,
        s_behavioral=s_b,
        s_vt=0,
        vt_pending=True,
    )
    ```
  * `aegis-backend/scripts/evaluate_models.py:L93, L150-L156 @ 8c42233`:
    ```python
    # Line 93: Layer 4 (VirusTotal) is skipped in offline mode.
    s_behavioral = evaluate_behavioral(payload)
    score = synthesize_composite_score(
        s_heuristic=s_heuristic,
        s_nlp=s_nlp,
        s_behavioral=s_behavioral,
        s_vt=0,
        vt_pending=True,
    )
    ```
  * `evidences/README.md:L65-L66 @ b192365`:
    > *"Layer 3 (Neutralized): Defaulted to neutral constant score $S_{behavioral} = 15$ due to absence of longitudinal client interaction telemetry. Layer 4 (Skipped): VirusTotal network lookups were bypassed in offline mode."*

---

### Item 2. Precision, F1, and Cue-Stripping Rules for Ablation Configs (E-07)
* **Exact Answer:**
  * **Precision and F1-Score for Every Configuration:**
    1. **Config 1: Heuristics Only**
       * Standard Text (Neutral Auth): Precision = **100.0%** | F1-Score = **91.30%** (Accuracy = 92.0%, Recall = 84.0%, FPR = 0.0%; TP = 42, TN = 50, FP = 0, FN = 8)
       * Cue-Stripped Text (Neutral Auth): Precision = **100.0%** | F1-Score = **85.06%** (Accuracy = 87.0%, Recall = 74.0%, FPR = 0.0%; TP = 37, TN = 50, FP = 0, FN = 13)
    2. **Config 2: Heuristics + XGBoost/RF**
       * Standard Text (Neutral Auth): Precision = **100.0%** | F1-Score = **73.42%** (Accuracy = 79.0%, Recall = 58.0%, FPR = 0.0%; TP = 29, TN = 50, FP = 0, FN = 21)
       * Cue-Stripped Text (Neutral Auth): Precision = **100.0%** | F1-Score = **73.42%** (Accuracy = 79.0%, Recall = 58.0%, FPR = 0.0%; TP = 29, TN = 50, FP = 0, FN = 21)
    3. **Config 3: Heuristics + DistilBERT**
       * Standard Text (Neutral Auth): Precision = **100.0%** | F1-Score = **100.0%** (Accuracy = 100.0%, Recall = 100.0%, FPR = 0.0%; TP = 50, TN = 50, FP = 0, FN = 0)
       * Cue-Stripped Text (Neutral Auth): Precision = **100.0%** | F1-Score = **100.0%** (Accuracy = 100.0%, Recall = 100.0%, FPR = 0.0%; TP = 50, TN = 50, FP = 0, FN = 0)
    4. **Config 4: Full Pipeline**
       * Standard Text (Neutral Auth): Precision = **100.0%** | F1-Score = **100.0%** (Accuracy = 100.0%, Recall = 100.0%, FPR = 0.0%; TP = 50, TN = 50, FP = 0, FN = 0)
       * Cue-Stripped Text (Neutral Auth): Precision = **100.0%** | F1-Score = **100.0%** (Accuracy = 100.0%, Recall = 100.0%, FPR = 0.0%; TP = 50, TN = 50, FP = 0, FN = 0)
  * **Exact Cue-Stripping Rules:**
    In `tools/run_phase_c_evaluations.py:L166-L172 @ 0c541f5`:
    ```python
    urgency_regex = re.compile(
        r"\b(urgent|urgently|immediate|immediately|suspend|suspended|suspension|locked|lock|"
        r"action required|within 24 hours|within 48 hours|compromised|expire|expires|deactivated|babala|mag-login)\b",
        re.IGNORECASE,
    )
    subject = urgency_regex.sub("", subject).strip()
    body = urgency_regex.sub("", body).strip()
    ```
* **Proof & Citations:**
  * `evidence/E-07_ablation/E-07_ablation_summary_20261108_0c541f5.csv:L1-L9 @ 0c541f5`
  * `evidence/E-07_ablation/E-07_ablation_log_20261108_0c541f5.log:L5-L14 @ 0c541f5`
  * `tools/run_phase_c_evaluations.py:L165-L172, L400-L435 @ 0c541f5`

---

### Item 3. Dataset Scope for Threshold Sensitivity Sweep (E-24)
* **Exact Answer:**
  * The threshold sweep was run on the **full 100-sample corpus** (`aegis-backend/data/test_dataset.csv`, consisting of 50 phishing and 50 legitimate samples). It was **NOT** run on a validation split.
* **Proof & Citations:**
  * `tools/run_phase_c_evaluations.py:L60, L303-L305, L333-L339, L463-L475 @ 0c541f5`:
    ```python
    DATA_PATH = BACKEND_DIR / "data" / "test_dataset.csv"
    ...
    with open(DATA_PATH, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    ...
    # Lines 333-339: neu_scores computed over all 100 rows
    for r in rows:
        res = evaluate_single_sample(r, neutral_auth=True, config="full")
        neu_scores.append(float(res["score"]))
    ...
    # Lines 463-475: E-24 sweep loop
    sweep_thresholds = [35, 45, 50, 55, 65, 75, 85]
    for th in sweep_thresholds:
        preds = [1 if s >= th else 0 for s in neu_scores]
        m = calc_metrics(labels, preds)
    ```
  * `evidence/E-24_threshold-sweep/E-24_threshold-sweep_log_20261108_0c541f5.log:L5-L12 @ 0c541f5`:
    Shows that at Threshold 35: `Recall = 100.00%`, `Precision = 84.75%`, `FPR = 18.00%`, with `TP = 50` and `FP = 9` (accounting for all 50 phishing and 50 legitimate samples: 50 TP + 9 FP + 41 TN + 0 FN = 100 total samples).

---

### Item 4. Execution of SpamAssassin, Enron, or Other Public Corpora
* **Exact Answer:**
  * **not run**.
  * No public benchmark corpora (SpamAssassin, Enron, Nazario, or CEAS) were ever executed or evaluated through the Aegis pipeline.
  * Milestone 4.3 in `implementation_plan.md` proposed benchmarking against SpamAssassin as an aspirational roadmap item, but this was never implemented. Mentions in `E-21` refer solely to public training corpora cited in NLP literature.
* **Proof & Citations:**
  * `evidence/E-21_model-provenance/E-21_model-provenance_20261107_320e9b3.md:L39 @ 320e9b3`:
    > *"Because public phishing benchmarks share historical seeds (e.g. Nazario, SpamAssassin, Enron, CEAS), an exact overlap check against original pre-training splits cannot be cryptographically proven without the full raw pre-training archive."*
  * `implementation_plan.md:L347, L392-L395 @ 0c541f5` (unexecuted milestone plan).
  * Comprehensive repository inspection confirms 0 evaluation scripts, outputs, or metrics exist for SpamAssassin or Enron.

---

### Item 5. Live Render Telemetry Re-measurement and Phase C Latency Scope
* **Exact Answer:**
  * **Render Live API Re-measurement:** **No**, the warm API round trip (0.70–1.38 s, median 896.6 ms) was **NOT re-measured** on the current build against Render.
  * **Date and Commit of Last Measurement:**
    * Date: **2026-10-23 12:15:00**
    * Commit: `8c42233da6027148ccf0f735d7217b991d18bc3c` (committed Oct 23, 2026 12:33:49 +0800; recorded in `evidences/06_live_health_ping.json` and committed in `b192365`).
  * **Scope of Phase C "latency avg 91.93 ms":**
    * It measures **in-process** local CPU execution time of Python function evaluation (`evaluate_single_sample` in `tools/run_phase_c_evaluations.py`). It measures the execution duration of Layer 1 (heuristics + ensemble), Layer 2 (ONNX DistilBERT CPU inference), Layer 3 (behavioral baseline clamp), and meta-classifier risk synthesis within the running Python process. It involves **zero HTTP network round-trip overhead**.
* **Proof & Citations:**
  * `evidences/06_live_health_ping.json:L2-L53 @ b192365`:
    ```json
    {
      "timestamp": "2026-10-23 12:15:00",
      "environment": "Render.com Web Service (Free Tier, Singapore/Oregon)",
      "live_api_analyze_telemetry": {
        "batch_size": 10,
        "latency_mean_ms": 926.4,
        "latency_median_ms": 896.6,
        "latency_min_ms": 700.6,
        "latency_max_ms": 1378.2
      }
    }
    ```
  * `aegis-backend/scripts/measure_live_api.py:L70-L105 @ 8c42233`
  * `tools/run_phase_c_evaluations.py:L181, L227 @ 0c541f5`:
    ```python
    t0 = time.time()
    urls = extract_url_strings(payload.links or [])
    ...
    elapsed_ms = (time.time() - t0) * 1000
    ```
  * `evidence/E-08_phishing-corpus-metrics/E-08_phishing-corpus-metrics_report_20261108_0c541f5.json:L36-L39 @ 0c541f5`:
    `"latency_avg_ms": 91.93`, `"latency_p50_ms": 91.13`.

---

## Section B: Transactional / Flower Shop Probes (E-09, E-34)

### Item 6. Authentication Setup and Metrics for Transactional Email Audit (E-34)
* **Exact Answer:**
  * **spfPass / dkimPass Setting:** Set to **neutral True** (`neutral_auth = True`, enforcing `spfPass = True` and `dkimPass = True`).
  * **13 Phishing Lures Results:** **TP = 13, FN = 0** (100.0% recall across all 13 phishing lures).
  * **Exact Composite Scores for the 8 Standalone-DistilBERT False Positives:**
    1. Sample ID 51 ("Your monthly Lazada invoice is ready"): DistilBERT $P_{\text{phish}} = 0.9986$ $\rightarrow$ **Composite Score = 36** (`composite_flag = 0`)
    2. Sample ID 57 ("Your monthly Lazada invoice is ready"): DistilBERT $P_{\text{phish}} = 1.0000$ $\rightarrow$ **Composite Score = 36** (`composite_flag = 0`)
    3. Sample ID 65 ("Your PhilHealth contribution receipt for October 2026"): DistilBERT $P_{\text{phish}} = 0.8053$ $\rightarrow$ **Composite Score = 29** (`composite_flag = 0`)
    4. Sample ID 84 ("Shopee Order Confirmation - Order #SHP-2026-12345"): DistilBERT $P_{\text{phish}} = 0.9958$ $\rightarrow$ **Composite Score = 36** (`composite_flag = 0`)
    5. Sample ID 85 ("Welcome to the Aegis SME Security Newsletter"): DistilBERT $P_{\text{phish}} = 0.9995$ $\rightarrow$ **Composite Score = 36** (`composite_flag = 0`)
    6. Sample ID 79 ("Team lunch - please confirm attendance"): DistilBERT $P_{\text{phish}} = 0.9679$ $\rightarrow$ **Composite Score = 35** (`composite_flag = 0`)
    7. Sample ID 52 ("Your monthly Lazada invoice is ready"): DistilBERT $P_{\text{phish}} = 0.9999$ $\rightarrow$ **Composite Score = 36** (`composite_flag = 0`)
    8. Sample ID 69 ("Your monthly Lazada invoice is ready"): DistilBERT $P_{\text{phish}} = 1.0000$ $\rightarrow$ **Composite Score = 36** (`composite_flag = 0`)
* **Proof & Citations:**
  * `tools/run_phase_c_evaluations.py:L154-L156, L527 @ 0c541f5`:
    ```python
    res = evaluate_single_sample(r, neutral_auth=True, config="full")
    ```
  * `evidence/E-34_transactional-fpr/E-34_transactional-fpr_report_20261108_0c541f5.txt:L1-L18 @ 0c541f5`
  * `evidence/E-34_transactional-fpr/E-34_transactional-fpr_summary_20261108_0c541f5.csv:L2-L48 @ 0c541f5`

---

### Item 7. Flower Shop Probe Features and Score Breakdown (E-09)
* **Exact Answer:**
  * **Probe Email Subject & Body:**
    * **Subject:** `Order Confirmation #2847 — Bloom & Petal Florist`
    * **Body:**
      ```text
      Dear Customer,

      Thank you for your order. Your arrangement of 12 red roses and baby's breath has been confirmed and will be delivered on Friday between 10 AM and 2 PM.

      Order total: PHP 850.00. Payment received via GCash.

      If you have any questions, reply to this email or call us at 0917-555-1234.

      Warm regards,
      Bloom & Petal Florist
      ```
  * **Features:**
    * Sender: First-time sender (`reason: "first_time_sender"`, no prior communication history).
    * Content: Zero urgency cues, zero typosquatting, zero attachments, zero hyperlinks (`urls = []`).
    * Cryptographic Auth: Synthetic SPF failure (`spfPass = False`, +25) and DKIM failure (`dkimPass = False`, +20).
  * **Score Breakdown:**
    * $S_{\text{h}} = \mathbf{45}$ (Layer 1: SPF failure +25, DKIM failure +20)
    * $S_{\text{nlp}} = \mathbf{60}$ (Layer 2 DistilBERT live inference: $P_{\text{phish}} = 0.9998$, $S_{\text{base}} = 59.99$, $S_{\text{urgency}} = 0$, $S_{\text{bec}} = 0$)
    * $S_{\text{b}} = \mathbf{25}$ (Layer 3: first-time sender behavioral anomaly baseline)
    * $S_{\text{vt}} = \mathbf{0}$ (Layer 4: no links/attachments; `vt_status = "completed"`, `vt_pending` evaluates to True, using preliminary normalization $\div 0.85$)
    * **Preliminary Normalization Formula:**
      $$R_{\text{preliminary}} = \text{round}\left(\frac{0.25 \times 45 + 0.45 \times 60 + 0.15 \times 25}{0.85}\right) = \text{round}\left(\frac{11.25 + 27.0 + 3.75}{0.85}\right) = \text{round}(49.41) = \mathbf{49}$$
    * **Floors Applied:**
      * **Heuristic Threat Floor**: $S_{\text{heuristic}} = 45 \ge 40$. Per `modules/meta_classifier.py:L351-L353`, because $S_{\text{h}} \ge 40$, a minimum floor of 52 is enforced when $R_{\text{preliminary}} < 52$.
      * Score $R_{\text{preliminary}} = 49$ was elevated to $R_{\text{final}} = \mathbf{52}$ (**Warning** tier).
* **Proof & Citations:**
  * `aegis-backend/scripts/flower_shop_nlp_probe.py:L54-L87, L218-L305 @ 54a8720 / 0c541f5`
  * `evidence/E-09_flower-shop-probe/E-09_flower-shop-probe_output_20261106_na.json:L1-L135 @ 54a8720`
  * `evidence/E-09_flower-shop-probe/E-09_flower-shop-probe_output_20261106_na.txt:L1-L105 @ 54a8720`
  * `aegis-backend/modules/meta_classifier.py:L351-L355 @ 799f152`

---

## Section C: Extension Behavior

### Item 8. Offline Fallback Logic and UI Representation
* **Exact Answer:**
  * **Checks that RUN locally** (in `aegis-extension/local_heuristics.js`):
    1. *Urgency & Coercive Keyword Density*: English + Tagalog/Taglish regex patterns (up to 30 pts).
    2. *Hyperlink Safety*: IP-based host (+35 pts), suspicious TLD (+20 pts), deceptive anchor text mismatch (+35 pts).
    3. *Sender Domain & Identity*: High-abuse sender TLD (+25 pts), free webmail spoofing (+30 pts), brand typosquatting via Levenshtein distance $\le 2$ or hyphenation (+35 pts), brand display-name mismatch (+25 pts).
    4. *Attachment Safety*: Dangerous executable/script extensions (+35 pts), archive extensions (+15 pts).
    5. *Authentication Flags*: `spfPass === false` (+25 pts), `dkimPass === false` (+20 pts).
    6. *Behavioral Telemetry*: Ingests client-side `behavioralScore`; if $\ge 20$, adds $\min(25, \text{round}(\text{score} \times 0.5))$ pts.
  * **Checks that DO NOT RUN offline**:
    * Layer 2 Deep NLP contextual semantics (DistilBERT ONNX model).
    * Layer 1 Tabular Machine Learning ensemble (Random Forest + XGBoost).
    * Layer 4 VirusTotal v3 cloud threat intelligence (live URL and file hash queries).
    * Server-side meta-classifier normalization.
  * **Does it show a tier or score?**:
    * **It shows BOTH a tier and a score**. It calculates a numeric score (0–100%) and maps it to Safe ($<45$), Warning ($45\text{--}74$), or Critical ($\ge 75$). The overlay renders the numerical score circle (`el.scoreValue.textContent = analysis.score`) and the categorical risk badge/gauge, accompanied by a prominent amber degraded-mode banner (`.aegis-degraded-mode-banner`).
* **Proof & Citations:**
  * `aegis-extension/background.js:L8, L22, L265-L285, L345-L392 @ 0c541f5`
  * `aegis-extension/local_heuristics.js:L10-L25, L33-L100, L230-L515 @ 0c541f5`
  * `aegis-extension/overlay/overlay.js:L493-L545, L826-L835, L888-L895, L1335-L1398 @ 0c541f5`
  * `aegis-extension/tests/test_degraded_mode.js:L60-L116 @ a6925ff`

---

### Item 9. Whitelist Engine Behavior on Null SPF/DKIM and Auto-Revocation Reachability
* **Exact Answer:**
  * **What happens when sender is whitelisted and extractAuthStatus() returns null:**
    * In `aegis-extension/whitelist/whitelist.js`, Trigger 2 checks `var authFailed = (spfPass === false) || (dkimPass === false);`.
    * When SPF/DKIM are `null`, `(null === false)` evaluates to `false`. Therefore `authFailed` is `false`.
    * Trigger 2 is bypassed, and the execution flows directly to the **clean whitelist hit**: returns `{ whitelisted: true, revoked: false, trigger: null, score: 5, riskLevel: 'Safe', riskClass: 'threat-safe', flag: 'VERIFIED: Sender Identity Whitelisted' }`. The sender is classified as **Safe** with score **5**.
  * **Is the auto-revocation guardrail reachable only when Gmail shows a warning banner?**:
    * **No, not exclusively**:
      * **Trigger 1 (Display-Name Spoofing)**: Operates independently of Gmail warning banners. If an email's display name matches a whitelisted VIP contact but the actual sender address belongs to an unauthorized domain, Trigger 1 auto-revocation triggers immediately and enforces score **95 (Critical)**.
      * **Trigger 2 (Cryptographic Auth Failure)**: In a live Gmail webmail session, Trigger 2 is reachable **only when Gmail displays a warning banner**. This is because Gmail's details table (`mailed-by`/`signed-by`) only sets flags to `true` or `null` (never `false`); the only DOM element that sets `spfPass = false` and `dkimPass = false` is Gmail's warning alert banner (`content_script.js:L214-L239`). (In automated tests, it is also reachable via test fixture attribute `data-aegis-spf="false"`).
* **Proof & Citations:**
  * `aegis-extension/whitelist/whitelist.js:L310-L385 (Trigger 1), L394-L428 (Trigger 2 and clean hit) @ 25af4bf / 0c541f5`
  * `aegis-extension/content_script.js:L198-L283 @ bf1e61e / 799f152`
  * `aegis-extension/overlay/overlay.js:L514-L531, L1357-L1370 @ 0c541f5`

---

### Item 10. PII Scrubber Invocation and Field Scope (E-03)
* **Exact Answer:**
  * **Is it actually invoked?**: **Yes**, `pii_scrubber.js` is invoked in `content_script.js` before dispatching the payload to `background.js` and `/api/v1/analyze`.
  * **Quoted Call Site** (`aegis-extension/content_script.js:L696-L702 @ 85e8e3a / 0c541f5`):
    ```javascript
    var sanitizedPayload = emailContext;
    if (typeof window.AegisPIIScrubber !== 'undefined' && typeof window.AegisPIIScrubber.scrubEmailPayload === 'function') {
      sanitizedPayload = window.AegisPIIScrubber.scrubEmailPayload(emailContext);
      if (sanitizedPayload.piiRedactionStats && sanitizedPayload.piiRedactionStats.total > 0) {
        console.log(LOG_PREFIX + ' PII scrubbing applied:', sanitizedPayload.piiRedactionStats);
      }
    }
    ```
  * **Does it scrub subject, body, links, or all three?**:
    * It scrubs **bodyText only** on the payload sent to `/api/v1/analyze`.
    * In `aegis-extension/pii_scrubber.js` (lines 195–221):
      * `bodyText`: Replaced by `bodyResult.scrubbedText` with PII tokens replaced by redaction placeholders (`[EMAIL]`, `[PHONE]`, `[CARD_NUMBER]`, `[SSN]`, `[NAME]`).
      * `subject`: `scrubText(emailPayload.subject)` is evaluated and assigned to `scrubbedSubject`, but the primary `subject` field is inherited from `...emailPayload` and is **NOT overwritten** (the raw subject remains intact).
      * `links`: **NOT scrubbed**; URLs are transmitted unmodified to allow link reputation and typosquatting inspection.
* **Proof & Citations:**
  * `aegis-extension/content_script.js:L696-L702 @ 85e8e3a / 0c541f5`
  * `aegis-extension/pii_scrubber.js:L195-L221 @ 85e8e3a / 0c541f5`
  * `evidence/E-03_backend-payload/E-03_backend-payload_refs_20261107_85e8e3a.md:L1-L62 @ 85e8e3a`

---

### Item 11. Analysis Result Cache Storage
* **Exact Answer:**
  * The result cache is stored in **`chrome.storage.local`** under key `'aegis_analysis_cache'` with an **LRU capacity ceiling of 100 entries** (`MAX_CACHE_ENTRIES = 100`) and a **7-day Time-To-Live (TTL)** (`CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000 = 604,800,000 ms`).
  * In non-extension environments (such as Node.js unit tests without `chrome.storage.local`), an in-memory dictionary fallback adapter is used.
* **Proof & Citations:**
  * `aegis-extension/background.js:L10, L23-L25, L96-L120, L142-L252 @ dfa2265 / 0c541f5`
  * `aegis-extension/tests/test_background_bridge.js:L130-L165 @ dfa2265`

---

### Item 12. Dashboard Preset Labels, Thresholds, and Tooltip Text
* **Exact Answer:**
  * **Naming Scheme:** The preset profiles are named **"Conservative/Standard/Aggressive"**. (The names "Relaxed/Balanced/Aggressive" are NOT used).
  * **Exact Labels, Thresholds, and Tooltip Text:**
    1. **Conservative Preset**:
       * Button ID: `preset-conservative`
       * Display Label: `Conservative`
       * Subtitle: `35% / 65% · High Protection`
       * Threshold Values: Warning $\ge \mathbf{35\%}$, Critical $\ge \mathbf{65\%}$ (`data-warn="35" data-crit="65"`)
       * Tooltip (`title` attribute): `"Conservative (High Protection): Warning ≥ 35%, Critical ≥ 65%. Prioritizes maximum threat interception. Recommended for financial, executive, or wire-transfer inboxes."`
    2. **Standard Preset (Default)**:
       * Button ID: `preset-standard`
       * Display Label: `Standard`
       * Subtitle: `45% / 75% · Balanced (Default)`
       * Threshold Values: Warning $\ge \mathbf{45\%}$, Critical $\ge \mathbf{75\%}$ (`data-warn="45" data-crit="75"`)
       * Tooltip (`title` attribute): `"Standard (Default): Warning ≥ 45%, Critical ≥ 75%. Balanced sensitivity for standard operational SME workflows."`
    3. **Aggressive Preset**:
       * Button ID: `preset-aggressive`
       * Display Label: `Aggressive`
       * Subtitle: `55% / 85% · Low Alert Volume`
       * Threshold Values: Warning $\ge \mathbf{55\%}$, Critical $\ge \mathbf{85\%}$ (`data-warn="55" data-crit="85"`)
       * Tooltip (`title` attribute): `"Aggressive (Low Alert Volume): Warning ≥ 55%, Critical ≥ 85%. Requires stronger multi-layer corroboration before alerting. Minimizes false alerts in high-volume environments."`
* **Proof & Citations:**
  * `aegis-extension/dashboard/dashboard.html:L188-L223 @ a824a4e / 0c541f5`
  * `aegis-extension/dashboard/dashboard.js:L515-L542 @ a824a4e / 0c541f5`

---

## Section D: Git History

### Item 13. Audit of Commit 326b02d and UAT Evaluation Build
* **Exact Answer:**
  * **Commit Hash:** `326b02d06d3ed0735dff93c87d84189e54e5ee4e`
  * **Commit Date:** **Mon Oct 5 01:48:21 2026 +0800**
  * **Commit Message:** `feat(prototype): complete Week 3.6 feature-complete prototype integration and validation suite (#15)`
  * **Feature Inclusion in 326b02d:**
    * *Two-tier XAI panel:* **YES** (includes floating warning banner top layer and expandable Full Analysis Modal / FAM breakdown with plain-language rationale in `overlay.js` / `overlay.css`).
    * *VirusTotal reasons:* **NO** (included preliminary async VT polling stubs, but specific VT engine detection reasons and attachment file hash lookups were not introduced until commit `56a8819` on Oct 23, 2026).
    * *Presets:* **NO** (presets and tooltips were added Nov 7, 2026 in commit `a824a4e`; dashboard did not exist until Oct 22 in `5357495`).
    * *Ensemble:* **NO** (RF / XGBoost ensemble classifier was introduced Oct 22 in commit `689c839`).
    * *SPF/DKIM extraction:* **NO** (Gmail DOM SPF/DKIM extraction was introduced Oct 22 in commit `bf1e61e`).
  * **Build Shown to UAT Participants on Oct 9, 2026:**
    * **Commit `326b02d`** (the functional prototype codebase as of Oct 5, 2026; the only intervening commit before Oct 10 was `d2a1088` on Oct 5, which updated documentation only).
* **Proof & Citations:**
  * `git show 326b02d --stat`
  * `evidence/E-17_post-defense-ui-commits/E-17_post-defense-ui-commits_20261107_a824a4e.txt:L10-L65 @ a824a4e`
  * `evidence/E-23_uat-data/E-23_uat-data_report_20261107_0c541f5.md:L9 @ 0c541f5`

---

### Item 14. Introduction Dates and Commits for Key UI and Backend Features
* **Exact Answer:**
  1. **Two-Tier XAI Panel:**
     * Overlay Banner & Modal Architecture: Commits `bef94c6` (Sun Sep 20 20:53:23 2026 +0800) and `fc0ea76` (Wed Sep 23 23:24:23 2026 +0800).
     * Plain-Language XAI Generator: Commit `d990bdd` (Thu Sep 24 06:24:40 2026 +0800).
     * Full Modal Integration & Zoom Controls: Commit `326b02d` (Mon Oct 5 01:48:21 2026 +0800).
  2. **VirusTotal Reasons Display:**
     * Preliminary Async VT Polling & UI Fold-In: Commit `8947afe` (Mon Sep 21 00:23:13 2026 +0800) and `d990bdd` (Thu Sep 24 06:24:40 2026 +0800).
     * PR-09 VT Cryptographic File Hash Analysis & Detailed Detection Reasons: Commit `56a8819` (Fri Oct 23 00:20:05 2026 +0800).
  3. **Presets (`a824a4e`):**
     * Commit `a824a4e`: **Sat Nov 7 22:33:13 2026 +0800** (`feat(dashboard): add Conservative/Standard/Aggressive sensitivity presets with tooltips (I-12)`).
  4. **SPF/DKIM "Not verified" Fix (`799f152`):**
     * Commit `799f152`: **Sat Nov 7 22:19:42 2026 +0800** (`feat(auth): fix SPF/DKIM null auth state to show 'Not verified' (I-01)`).
  5. **Model-Loaded Guard (`160d746`):**
     * Commit `160d746`: **Sat Nov 7 21:12:02 2026 +0800** (`feat(I-02): model-loaded guard in health endpoint + evaluation report provenance`).
* **Proof & Citations:**
  * `evidence/E-17_post-defense-ui-commits/E-17_post-defense-ui-commits_20261107_a824a4e.txt:L10-L105 @ a824a4e`
  * Git history for commits `a824a4e`, `ef29590`, `799f152`, `160d746`, `56a8819`, `326b02d`, `d990bdd`.

---

## Section E: Model Provenance and Data (E-21, E-20, E-33)

### Item 15. DistilBERT Provenance, Template Overlap, Ensemble Training, and Leakage
* **Exact Answer:**
  * **DistilBERT Checkpoint Training Datasets:**
    * Pre-trained checkpoint: `lemonade-sdk/phishing-email-detection-distilbert-ONNX` (Hugging Face, Apache-2.0 license). Fine-tuned on public phishing and legitimate email collections prior to ONNX export/quantization.
  * **Known Overlap with `test_dataset.csv` Templates:**
    * As stated in Model Card Section 3 (`evidence/E-21_model-provenance/E-21_model-provenance_20261107_320e9b3.md:L39`):
      *"Because public phishing benchmarks share historical seeds (e.g. Nazario, SpamAssassin, Enron, CEAS), an exact overlap check against original pre-training splits cannot be cryptographically proven without the full raw pre-training archive. Consequently, benchmark scores reported on synthetic evaluation datasets (`data/test_dataset.csv`) must be interpreted as laboratory validation metrics rather than zero-shot field generalizability."*
    * `test_dataset.csv` templates were procedurally generated for Philippine SME contexts, so there is no known literal overlap, but isolation from public pre-training corpora cannot be mathematically guaranteed.
  * **RF / XGBoost Training Script, Seed, and Split:**
    * **Training Script:** `aegis-backend/scripts/train_ensemble.py`
    * **Random Seed:** `42` (`rng = np.random.default_rng(42)`, `random_state=42`)
    * **Train / Test Split:** Stratified 80/20 train/test split (`test_size=0.20, random_state=42, stratify=y`), producing **800 training samples and 200 testing samples** from a 1,000-sample balanced synthetic distribution, with 5-fold cross validation (`StratifiedKFold(5, shuffle=True, random_state=42)`).
  * **Leakage Check Result:**
    * Cross-validation on the synthetic feature vectors achieved F1 = 1.0000 due to distinct synthetic cluster separation.
    * On `test_dataset.csv`, **label leakage via synthetic authentication flags** was discovered: 100% of phishing emails had `spfPass=False, dkimPass=False` and 100% of legitimate emails had `spfPass=True, dkimPass=True`. Under neutral authentication controls (`spfPass=True, dkimPass=True`), standalone heuristics recall dropped from 86.0% to 66.0% (and ensemble accuracy was 79.0%), whereas the full pipeline maintained 100.0% recall through DistilBERT neural classification.
* **Proof & Citations:**
  * `evidence/E-21_model-provenance/E-21_model-provenance_20261107_320e9b3.md:L10-L43 @ 320e9b3`
  * `aegis-backend/scripts/train_ensemble.py:L105-L170, L195-L245 @ 689c839 / 799f152`
  * `aegis-backend/scripts/train_report.txt:L1-L55 @ 689c839`
  * `evidences/README.md:L50-L62 @ b192365`

---

### Item 16. Test Dataset Labeling Provenance and Inter-Rater Reliability
* **Exact Answer:**
  * **Who Labelled `test_dataset.csv`**: Ground-truth labels ($0 = \text{Legitimate}, 1 = \text{Phishing}$) were assigned during prototype development by the student development team (lead author/developer).
  * **How Labelled (by Template Class?)**: Labelled systematically by template class: emails were synthesized from structured template banks across 9 predefined functional categories (Transactional Notifications, Malicious Attachments, Account Panic, Credential Harvesting, BEC/Wire Fraud, Business Inquiries, Routine Internal, Lottery Baiting, Newsletters) and targeted Philippine brands (BPI, GCash, BDO, Shopee, Lazada, Maya, SSS, PhilHealth). All 50 phishing templates were assigned class `1`, and all 50 benign templates were assigned class `0`.
  * **Second Annotator / Cohen's Kappa:** **No second annotator was used**, and a formal inter-rater reliability agreement (such as Cohen's Kappa or Fleiss' Kappa) was **NOT conducted**.
* **Proof & Citations:**
  * `evidence/E-33_inter-rater/E-33_inter-rater_report_20261107_a482063.md:L8-L38 @ a482063`:
    > *"A formal dual-blind inter-rater reliability study (such as Cohen's Kappa or Fleiss' Kappa) was NOT conducted across independent human annotators for the 100-sample test dataset (`test_dataset.csv`)."*
  * `evidence/E-20_test-set-composition/E-20_test-set-composition_report_20261107_91e1e8d.md:L10-L55 @ 91e1e8d`
  * `evidences/README.md:L44-L48 @ b192365`

---

### Item 17. LLM Generation of Phishing Test Samples (E-20 Quote)
* **Exact Answer:**
  * **Were any of the 50 phishing samples LLM-generated?**: **No**, zero phishing samples were generated by an LLM.
  * **Exact Quote from Evidence Records (`evidences/README.md:L44-L47 @ b192365` & `E-20` provenance)**:
    > *"The test dataset consists of 100 emails procedurally generated from structured template banks (GCash, BDO, BPI, Maya, Shopee, SSS, Taglish lures, wire fraud, and benign transactional/interpersonal emails). No live LLM API (e.g., ChatGPT/Claude) was invoked dynamically during test sample generation; all emails were template-synthesized."*
* **Proof & Citations:**
  * `evidence/E-20_test-set-composition/E-20_test-set-composition_report_20261107_91e1e8d.md:L14-L60 @ 91e1e8d`
  * `evidences/README.md:L44-L48 @ b192365`

---

## Section F: Attachments and UAT

### Item 18. Attachment Hash-Lookup Check for .xlsm / .docx / .pdf Files
* **Exact Answer:**
  * **not run**.
  * An empirical hash-lookup evaluation across `.xlsm`, `.docx`, and `.pdf` attachments was **not run**.
  * Attachment hash evaluation was restricted to unit test suites (`aegis-extension/tests/test_attachment_hash.js` and `aegis-backend/tests/test_attachment_vt.py`) using sample `.exe`, `.pdf`, and `.zip` mock fixtures. In Revision Matrix v16 (line 326), this is explicitly documented:
    *"Limitations/Scope states that .xlsm, .docx, and .pdf attachments were not evaluated, with testing focused on compressed .zip archives. Client-side hashing relies on VirusTotal hash reputation... Zero-day attachment risk (macro malware not yet cataloged by VirusTotal) is documented as an architectural boundary in Chapter 5."*
* **Proof & Citations:**
  * `tools/build_revision_matrix_v16.py:L326-L330, L605-L606 @ 0c541f5`
  * `aegis-extension/tests/test_attachment_hash.js:L85-L130 @ 56a8819 / 799f152`
  * `aegis-backend/data/vt_file_seed_cache.json:L1-L45 @ 56a8819`

---

### Item 19. Administration of System Usability Scale (SUS) Questionnaire
* **Exact Answer:**
  * **No**, a System Usability Scale (SUS) questionnaire (Brooke, 1996; 10-item psychometric scale) was **never administered**.
  * The UAT usability evaluation administered a **4-item custom Likert questionnaire** evaluated on a 5-point scale (1 = Poor/Disruptive to 5 = Highly Favorable/Seamless) across $N = 6$ participants (3 business owners, 3 operational staff across 3 micro/small businesses) on October 9, 2026:
    * Q1: Processing Speed (Combined Mean = 4.67 / 5.0)
    * Q2: Perceived Accuracy (Combined Mean = 4.67 / 5.0)
    * Q3: XAI Comprehension (Combined Mean = 4.67 / 5.0)
    * Q4: Workflow Non-Intrusiveness (Combined Mean = 4.67 / 5.0)
    * Overall Composite Usability: 4.67 / 5.0 (93.3%)
* **Proof & Citations:**
  * `evidence/E-23_uat-data/E-23_uat-data_report_20261107_0c541f5.md:L1-L60 @ 0c541f5`
  * `evidence/E-23_uat-data/E-23_uat-data_anonymized_20261107_0c541f5.csv:L1-L7 @ 0c541f5`
  * Source survey export: `Aegis-Phishing-Context-Analyzer (Responses).xlsx` (SHA-256: `7e7a21a212262f126bea6e8d888bf32aa21d3207da9fabe6cbe3a4218fac64fc`)

---

## Section G: Pending Screenshots

### Item 20. Reproduction Steps and Target State for Screenshots E-13, E-15, E-16
* **Exact Answer:**
  1. **Screenshot E-13: Two-Tier XAI Panel**
     * **URL / State:** Open Gmail in Google Chrome (`https://mail.google.com/mail/u/0/#inbox`) with Aegis extension loaded (`chrome://extensions` $\rightarrow$ Developer Mode $\rightarrow$ Load unpacked `aegis-extension`) and backend active (`http://localhost:8000`).
     * **Reproduction Steps:**
       1. Open any flagged phishing email (e.g. `demo_emails/03_CRITICAL_credential_harvesting_link.md`).
       2. The top-tier floating neo-brutalist warning banner (`#aegis-overlay-banner`) appears above the email body displaying the composite score and plain-language summary.
       3. Click the **"Full Analysis"** / **"Details"** button (`#aegis-full-analysis-btn`).
       4. The Full Analysis Modal (FAM) opens over Gmail.
     * **Capture State:** Capture the modal displaying Tier 1 (Plain-Language Executive Summary at top) and Tier 2 (Expandable multi-factor layer breakdown drawers: Layer 1 Structural & Auth, Layer 2 Attachment Check, Layer 3 Behavioral Anomaly, Layer 4 Deep NLP Context).
  2. **Screenshot E-15: VirusTotal Reasons Panel**
     * **URL / State:** Same as above on Gmail (`https://mail.google.com/*`) with backend active.
     * **Sample Email Triggering VirusTotal-Flagged Link:**
       * **Sender:** `alerts@security-paypal-notice.com`
       * **Subject:** `URGENT: Suspicious transaction detected - verify identity`
       * **Flagged URL in Body:** `http://paypal-verification-account-sec.com/login`
         *(Found in `aegis-backend/data/vt_seed_cache.json` with 18/75 malicious vendor detections, category `phishing_credential_harvesting`. Alternative link: `http://office365-password-reset-portal.co/login`, 26/75 vendor detections).*
     * **Reproduction Steps:**
       1. Open email containing `http://paypal-verification-account-sec.com/login`.
       2. Allow 3–5 seconds for the background VirusTotal polling routine (`AEGIS_CHECK_VT_STATUS`) to complete and fold into the UI.
       3. Open the Full Analysis Modal.
       4. Expand the **"Layer 4 / Hyperlink Analysis"** drawer or inspect the Threat Indicators list.
     * **Capture State:** Capture the panel displaying the explicit VirusTotal vendor ratio and plain-language category reasons: `"VirusTotal link reputation: 18/75 security vendors flagged destination as malicious (phishing_credential_harvesting)"`.
  3. **Screenshot E-16: Threshold Presets with Tooltip**
     * **URL / State:** `chrome-extension://<extension-id>/dashboard/dashboard.html` in Google Chrome (opened via extension popup $\rightarrow$ "Settings / Dashboard" or direct URL).
     * **Reproduction Steps:**
       1. Navigate to the SME Security Analytics Dashboard.
       2. Scroll down to the **"Risk Tier Sensitivity"** card (`#sens-presets-wrap`).
       3. Hover the mouse cursor over the `preset-conservative` button (or `preset-standard` / `preset-aggressive`).
     * **Capture State:** Capture the Guided Protection Profiles group showing the three preset buttons (`Conservative 35%/65%`, `Standard 45%/75%`, `Aggressive 55%/85%`) with the native browser tooltip visibly displayed: `"Conservative (High Protection): Warning ≥ 35%, Critical ≥ 65%. Prioritizes maximum threat interception. Recommended for financial, executive, or wire-transfer inboxes."`
* **Proof & Citations:**
  * `aegis-extension/overlay/overlay.js:L1050-L1400 @ 326b02d / 0c541f5`
  * `aegis-extension/dashboard/dashboard.html:L188-L223 @ a824a4e`
  * `aegis-extension/dashboard/dashboard.js:L515-L542 @ a824a4e`
  * `aegis-backend/data/vt_seed_cache.json:L1-L35 @ 8e9ce12 / 0c541f5`
  * `demo_emails/03_CRITICAL_credential_harvesting_link.md:L1-L48 @ 326b02d`
  * `tools/build_revision_matrix_v16.py:L243-L255, L326-L331, L510-L517 @ 0c541f5`

