# AEGIS FINAL INTEGRITY REPORT (FINAL_INTEGRITY_REPORT.md)

**Execution Date:** 2026-11-09T05:24:00Z  
**Repository Working Directory:** `c:\Users\jafph\Desktop\Capstone 1 - Phishing Analyzer\Aegis-Phishing-Context-Analyzer`  
**Git HEAD Reference Commit:** `19affee1814c882d8b80390746995777453bc45e`  
**Active Git Branch:** `post-submission-eval` (ahead of origin by 33 commits)  
**Evaluator:** Antigravity (Defensive AI Architecture Audit Agent)  
**Operating Policy:** READ-ONLY pass observed. Zero production code alterations. Zero force-pushes or history rewrites.

---

## EXECUTIVE SUMMARY: MISMATCHES, DISCLOSURES & PENDING ACTIONS

| Integrity Check Category | Finding / Status | Detail & Forensic Reference |
|---|:---:|---|
| **Mismatches in Core Logic / Thresholds** | **NONE (0 Mismatches)** | All 15 core architectural claims evaluated in Step 3 are verified exact matches against runtime source code. |
| **Production Source Logic Alterations** | **NONE (0 Changes)** | `git diff aegis-extension/ aegis-backend/modules/ aegis-backend/routes/` returns 0 changes. |
| **Secrets in Git History** | **CLEAN (0 Committed)** | Live VirusTotal API key was never committed to version control in any commit. |
| **Secrets in Working Tree (Pending Action)** | **⚠️ FLAGGED (2 Files)** | Live 64-character VirusTotal API key is present in `aegis-backend/.env:8` (gitignored) and `evidence/AUDIT_ROUND4.md:250,271` (untracked). Values masked in reports. |
| **Withdrawn Evidence** | **WITHDRAWN (2 E-IDs)** | `E-05` and `E-06` formally marked **`WITHDRAWN`** due to model-loaded guard non-compliance in initial runs. |
| **Superseded Calibration** | **SUPERSEDED (1 Report)** | Round 3 fallback calibration `E-39_train_calibration_report.json` initial run marked **`SUPERSEDED`** by post-`19affee` warm-model rerun. |
| **Data Overlap / Contamination** | **CONTAMINATED (1 File)** | `evidence/E-39_independent-corpus/nazario_only_eval.json` has 10 of 25 Nazario test samples (40.0%) overlapping with `E-39_dataset_train_200.csv`. Formally marked **`CONTAMINATED`**. |
| **Step 7 Submission Tagging** | **PENDING USER APPROVAL** | Read-only protocol strictly maintained; no commits staged, no branch created, no tag pushed until written user approval. |

---

## 1. REPO TRIAGE & PENDING CHANGES AUDIT

### 1.1 Classification of All Pending Working-Tree Changes

| Category | File Path | Git Status | Recommended Action |
|---|---|:---:|---|
| **Evaluation Scripts** | `aegis-backend/scripts/measure_live_api.py` | Modified | Stage in `eval-tools` commit (updates live Render telemetry harness). |
| **Evaluation Scripts** | `tools/calibrate_warning_cutoff.py` | Modified | Stage in `eval-tools` commit (adds DistilBERT warm=True guard). |
| **Evaluation Scripts** | `tools/run_round2_evaluations.py` | Modified | Stage in `eval-tools` commit (adds DistilBERT warm=True guard). |
| **Evaluation Scripts** | `tools/evaluate_nazario_only.py` | Untracked | Stage in `eval-tools` commit (harness for Nazario evaluation). |
| **Evaluation Scripts** | `tools/evaluate_all_sets_calibrated.py` | Untracked | Stage in `eval-tools` commit (multi-set calibration runner). |
| **Evaluation Scripts** | `tools/check_nazario_sources.py` | Untracked | Stage in `eval-tools` commit (Nazario source inspector). |
| **Evaluation Scripts** | `tools/compute_auc.py` | Untracked | Stage in `eval-tools` commit (ROC-AUC calculation helper). |
| **Evaluation Scripts** | `tools/rebuild_nazario_positive.py` | Untracked | Stage in `eval-tools` commit (Nazario positive set extractor). |
| **Evaluation Scripts** | `tools/run_live_vt_subset.py` | Untracked | Stage in `eval-tools` commit (live VT subset runner). |
| **Evaluation Scripts** | `tools/trace_table10_e08.py` | Untracked | Stage in `eval-tools` commit (manuscript Table 10 tracer). |
| **Evaluation Scripts** | `tools/build_revision_matrix_v16.py` | Untracked | Stage in `eval-tools` commit (faculty matrix builder). |
| **Evaluation Scripts** | `tools/update_revision_matrix_v17.py` | Untracked | Stage in `eval-tools` commit (faculty matrix v17 updater). |
| **Evidence Artifacts** | `evidence/AUDIT_ROUND2.md` | Modified | Stage in `evidence-docs` commit (academic wording update). |
| **Evidence Artifacts** | `evidence/E-39_independent-corpus/E-39_train_calibration_report.json` | Modified | Stage in `evidence` commit (warm model calibration output). |
| **Evidence Artifacts** | `evidence/E-39_round2_master_summary.json` | Modified | Stage in `evidence` commit (Round 2 master summary). |
| **Evidence Artifacts** | `evidence/E-43_llm-authored-eval/E-43_llm_generation_prompts.json` | Modified | Stage in `evidence` commit (prompt disclosure record). |
| **Evidence Artifacts** | `evidence/E-44_explainability-protocol/*.md, .csv` (6 files) | Modified | Stage in `evidence` commit (plain-language protocol documentation). |
| **Evidence Artifacts** | `evidences/06_live_health_ping.json` | Modified | Stage in `evidence` commit (Render live telemetry ping). |
| **Evidence Artifacts** | `evidence/AUDIT_FOR_MANUSCRIPT.md` | Untracked | Stage in `evidence-docs` commit (faculty audit report). |
| **Evidence Artifacts** | `evidence/AUDIT_ROUND3.md` | Untracked | Stage in `evidence-docs` commit (Round 3 audit report). |
| **Evidence Artifacts** | `evidence/AUDIT_ROUND4.md` | Untracked | **REDACT LINE 250 & 271 BEFORE STAGING** (contains live VT key). |
| **Evidence Artifacts** | `evidence/AUDIT_ROUND5.md` | Untracked | Stage in `evidence-docs` commit (Round 5 audit report). |
| **Evidence Artifacts** | `evidence/E-07_ablation/*` (2 files) | Untracked | Stage in `evidence` commit (stamped Phase C ablation logs). |
| **Evidence Artifacts** | `evidence/E-08_phishing-corpus-metrics/*` (3 files) | Untracked | Stage in `evidence` commit (stamped Phase C benchmark reports). |
| **Evidence Artifacts** | `evidence/E-23_uat-data/*` (2 files) | Untracked | Stage in `evidence` commit (stamped UAT reports and anonymized CSV). |
| **Evidence Artifacts** | `evidence/E-24_threshold-sweep/*` (2 files) | Untracked | Stage in `evidence` commit (stamped threshold sweep logs). |
| **Evidence Artifacts** | `evidence/E-32_nfr04-sample-size/*` (2 files) | Untracked | Stage in `evidence` commit (NFR04 sample size calculations). |
| **Evidence Artifacts** | `evidence/E-34_transactional-fpr/*` (2 files) | Untracked | Stage in `evidence` commit (stamped transactional FPR reports). |
| **Evidence Artifacts** | `evidence/E-39_independent-corpus/*` (4 files) | Untracked | Stage in `evidence` commit (`nazario_only_eval.json` marked CONTAMINATED). |
| **Evidence Artifacts** | `evidence/E-40_layers-3-and-4/*` (2 files) | Untracked | Stage in `evidence` commit (live VT evaluation data). |
| **Evidence Artifacts** | `evidence/E-45_small-fixes/*` (2 files) | Untracked | Stage in `evidence` commit (Render 30-warm/3-cold telemetry). |
| **Evidence Artifacts** | `evidences/09_flower_shop_nlp_probe.*` (2 files) | Untracked | Stage in `evidence` commit (probe probe logs). |
| **Data & Corpora** | `data/external_corpora/` | Untracked | Add to `.gitignore` (large raw zip/mbox files: 72 MB). |
| **Data & Corpora** | `data/SHA256SUMS` | Untracked | Stage in `datasets` commit. |
| **Documentation** | `AGENT_LOG.md` | Untracked | Stage in `docs` commit (agent execution audit trace). |
| **Documentation** | `LIVE_DEMONSTRATION_GUIDE.md` | Untracked | Stage in `docs` commit (faculty defense live demo instructions). |
| **Documentation** | `REPRODUCE.md` | Untracked | Stage in `docs` commit (complete reproduction instructions). |
| **Documentation** | `AI_USE.md` | Untracked | Stage in `docs` commit (academic AI attribution ledger). |
| **Documentation** | `evidence/MANIFEST.md` | Untracked | Stage in `evidence-docs` commit (master evidence manifest). |
| **Institutional Files** | `Aegis-Phishing-Context-Analyzer (Responses).xlsx` | Untracked | Keep untracked / add to `.gitignore` (raw spreadsheet). |
| **Institutional Files** | `MO-IT200D2 _ A4102 ... Progress Report Sheet.xlsx` | Untracked | Keep untracked / add to `.gitignore` (course progress sheet). |
| **Temporary / Junk** | `aegis-backend/results/` (5 files) | Untracked | Add to `.gitignore` or stage in supplementary results. |
| **Temporary / Junk** | `extracted_media/`, `final docs/` | Untracked | Add to `.gitignore` (loose Word extraction assets). |
| **Temporary / Junk** | `scratch/find_label_leakage.py` | Untracked | Add `scratch/` to `.gitignore`. |
| **Configuration** | `pyrightconfig.json` | Untracked | Stage in repository root configuration. |

### 1.2 Verification of Production Source Logic
- **Scoring, Thresholds & Weights Check:**
  - `git diff aegis-extension/` $\rightarrow$ **0 files changed**.
  - `git diff aegis-backend/modules/` $\rightarrow$ **0 files changed**.
  - `git diff aegis-backend/routes/` $\rightarrow$ **0 files changed**.
  - `git diff aegis-backend/main.py` $\rightarrow$ **0 files changed**.
- **Conclusion:** **ZERO** changes to scoring, threshold cutoffs, empirical layer weights, threat floors, sensitivity presets, or Chrome Extension UI behaviors exist in pending changes.

---

## 2. SECRETS & SENSITIVE DATA SCAN

A recursive automated scan of the full working tree and complete git history was executed targeting API keys, tokens, `.env` variables, student identifiers, and personal email addresses.

### 2.1 Git History Scan (`git log -S`)
- **VirusTotal API Key Pattern (`cac91e1d...`):** **CLEAN.** Never committed in any commit across any branch.
- **`.env` File History:** **CLEAN.** `aegis-backend/.env` has been excluded by `.gitignore` since repository initialization.
- **Sensitive Strings in History:** Commit `a8a5c7c` references regex validator `SECRET = re.compile(...)` in `tools/evidence_manifest.py`. No real secrets.

### 2.2 Working-Tree Scan Findings

| File Path | Line Number | Finding Type | Commit Status | Remediation Required |
|---|:---:|---|:---:|---|
| `aegis-backend/.env` | Line 8 | Live 64-character VirusTotal API Key (`VT_API_KEY=cac91e1d...`) | Working Tree Only (Excluded by `.gitignore`) | **DO NOT STAGE.** Ensure `.gitignore` continues to exclude `.env`. |
| `evidence/AUDIT_ROUND4.md` | Line 250, 271 | Live 64-character VirusTotal API Key referenced in markdown prose | Working Tree Only (Untracked) | **MUST REDACT** to `[MASKED_VT_KEY]` before staging `AUDIT_ROUND4.md`. |
| `aegis-backend/.env.example` | Line 61 | Generic placeholder (`VT_API_KEY=your_virustotal_api_key_here`) | Tracked (`7fd1a90`) | None (harmless template). |
| `start_backend.bat` | Line 13 | Console prompt string (`echo 3. Set VT_API_KEY={your-virustotal-api-key}`) | Tracked (`326b02d`) | None (instructional prompt). |

### 2.3 Emails and Personal Identifiers
- **Git Commit Authors:**
  - `jafgrengia@gmail.com` (Jafphet Grengia, Lead Developer)
  - `lr.jgrengia@mmdc.mcl.edu.ph` (Institutional student address)
  - `157719355+Jaffyyyyyy@users.noreply.github.com` (GitHub noreply alias)
- **Academic Attribution in Documentation:**
  - `README.md:13,268`, `manifest.json:6`, `implementation_plan.md:8`: Explicit human proponent attribution (**Jafphet P. Grengia** & **Michael Angelo L. Bernardo**, Mapúa Malayan Digital College). This is mandatory academic authorship, not a privacy leak.
- **User Acceptance Data (E-23):**
  - `evidence/E-23_uat-data/E-23_uat-data_anonymized_20261107_0c541f5.csv`: Fully anonymized (`R01` to `R06`, `SME-01` to `SME-03`). Zero participant names or emails present.
  - `Aegis-Phishing-Context-Analyzer (Responses).xlsx`: Untracked spreadsheet in root directory. Contains `Email Address withheld for privacy` in survey columns. Recommended action: keep untracked.

---

## 3. CLAIMS LEDGER (16 SPECIFICATION CLAIMS AUDITED)

Each claim from repository and paper specifications was audited against concrete lines of code in active files and verified with creation commits.

### Claim 1: Thresholds 45/75; Tiers Safe <= 44, Warning 45-74, Critical >= 75
- **Status:** **`MATCH`**
- **File & Lines:** `aegis-backend/modules/meta_classifier.py:31–33, 101–130`
- **Commit:** `d990bdd` (Milestone 3.4)
- **Code Proof:**
  ```python
  TIER_SAFE_MAX: int = 44        # Score < 45 -> Safe
  TIER_WARNING_MAX: int = 74     # Score 45-74 -> Warning
                                 # Score >= 75 -> Critical
  if bounded <= TIER_SAFE_MAX:
      return ("Safe", "risk-safe", "No significant threats detected...")
  elif bounded <= TIER_WARNING_MAX:
      return ("Warning", "risk-warning", "Suspicious characteristics detected...")
  else:
      return ("Critical", "risk-critical", "High-probability phishing attempt detected...")
  ```
- **Extension Match:** `aegis-extension/local_heuristics.js:504–512` mirrors: `finalScore >= 75 -> Critical`, `finalScore >= 45 -> Warning`, else `Safe`.

### Claim 2: Weights 0.25/0.45/0.15/0.15; Layer 1 Blend 0.60/0.40
- **Status:** **`MATCH`**
- **File & Lines:** `aegis-backend/modules/meta_classifier.py:22–25, 78–83`; `aegis-backend/modules/ensemble_classifier.py:12, 196`
- **Commits:** `d990bdd` (meta-classifier), `689c839` (ensemble classifier)
- **Code Proof:**
  ```python
  # meta_classifier.py:L22-25
  WEIGHT_HEURISTIC: float = 0.25
  WEIGHT_NLP: float = 0.45
  WEIGHT_BEHAVIORAL: float = 0.15
  WEIGHT_VT: float = 0.15

  # ensemble_classifier.py:L12, 196
  S_layer1_final = 0.60 * S_heuristic + 0.40 * S_ensemble
  ```

### Claim 3: Threat Floors: VT Malicious -> 75, Malicious Hash -> 75, Combined Attachment+Urgency -> 52, Heuristic >= 40 -> 52
- **Status:** **`MATCH`**
- **File & Lines:** `aegis-backend/modules/meta_classifier.py:86–93, 412–421, 428–446`
- **Commits:** `d990bdd` (VT floor), `56a8819` (malicious hash floor), `0c541f5` (multi-indicator floor)
- **Code Proof:**
  - **VT Malicious Floor (>=50 $\rightarrow$ 75):** `if critical_floor and s_vt >= 50 and final_score < 75: final_score = 75` (Line 86, 92).
  - **Attachment Hash Floor (Malware $\rightarrow$ 75):** `if has_malicious_attachment and final_score < 75: final_score = 75` (Line 415, 420).
  - **Multi-Indicator Warning Floor (Attachment + Urgency OR Heuristic >= 40 $\rightarrow$ 52):**
    ```python
    if (has_attachment_threat and has_urgency_threat) or s_heuristic >= 40:
        if final_score < 52:
            final_score = 52
    ```

### Claim 4: SPF +25, DKIM +20 Only When Exactly False; Null Ignored
- **Status:** **`MATCH`**
- **File & Lines:** `aegis-extension/local_heuristics.js:457–476`; `aegis-backend/routes/analyze.py:307–321`
- **Commits:** `bf1e61e` (extension DOM auth), `799f152` (null auth handling)
- **Code Proof:**
  ```javascript
  // local_heuristics.js:L457-476
  if (emailContext.spfPass === false) {
    flags.push({ id: 'RULE_SPF_FAIL', points: 25, ... });
    totalPoints += 25;
  }
  if (emailContext.dkimPass === false) {
    flags.push({ id: 'RULE_DKIM_FAIL', points: 20, ... });
    totalPoints += 20;
  }
  ```
  In both extension and backend, checking `=== false` / `is False` ensures `None`, `null`, and `undefined` trigger zero penalty.

### Claim 5: Behavioral Scores 25/15/5/0; Off-Hours +20 (>6 h); Weekend +10; Novel Attachment +15; Neutral Default 15
- **Status:** **`MATCH`**
- **File & Lines:** `aegis-extension/content_script.js:504–625`; `aegis-extension/tests/test_behavioral_baseline.js:7–220`
- **Commits:** `85084b4` (behavioral engine), `23d002a` (weekend and attachment novelty)
- **Code Proof:**
  - First-time sender (`count == 0`): `score = 25` (`content_script.js:543`)
  - Unfamiliar sender (`count in [1, 2]`): `score = 15` (`content_script.js:562`)
  - Warming-up sender (`count in [3, 4]`): `score = 5` (`content_script.js:578`)
  - Established sender (`count >= 5`): `score = 0` (`content_script.js:574`)
  - Null/empty sender default: `score = 15` (`content_script.js:518`)
  - Off-hours anomaly: `minDist > 6h` $\rightarrow$ `+20` points (`content_script.js:591–594`)
  - Weekend anomaly: `isWeekend` $\rightarrow$ `+10` points (`content_script.js:602–604`)
  - Novel attachment anomaly: unexpected extension $\rightarrow$ `+15` points (`content_script.js:616–619`)
  - Verified by 45 passing behavioral unit tests.

### Claim 6: NLP: 4-Class, P_phish=P(1)+P(3), S_base Formula, 512 Tokens, Checkpoint Name and SHA-256
- **Status:** **`MATCH`**
- **File & Lines:** `aegis-backend/modules/nlp_classifier.py:9–19, 35–45, 140–180`; `aegis-backend/scripts/download_model.py:24`; `evidence/E-21_model-provenance/E-21_model-provenance_20261107_320e9b3.md`
- **Commits:** `da7f4d5` (DistilBERT ONNX module), `85e8e3a` (model provenance)
- **Code & Asset Proof:**
  - 4 Classes: `0: legitimate_email`, `1: phishing_url_context`, `2: legitimate_url_context`, `3: alternative_phishing`.
  - Formulation: `P_phish = float(probs[1] + probs[3])`.
  - Base Score: `S_base = 60.0 * P_phish if P_phish > 0.50 else 10.0 * (1.0 - P_phish)`.
  - Max Tokens: `MAX_SEQUENCE_LENGTH = 512`.
  - Hugging Face Checkpoint: `lemonade-sdk/phishing-email-detection-distilbert-ONNX`.
  - Artifact File: `aegis-backend/models/phishing_distilbert/model.onnx` (Size: 267,938,324 bytes).
  - Artifact SHA-256: `361ebc80a1aa7f48778ad007abed802f93fc807ffbd741e8661cf3837c200db0`.

### Claim 7: Ensemble: 17 Features, 1000 Synthetic Vectors, 800/200 Split, Seed 42
- **Status:** **`MATCH`**
- **File & Lines:** `aegis-backend/scripts/train_ensemble.py:21–42, 60–80, 165–185`; `aegis-backend/modules/ensemble_classifier.py:21–42`
- **Commit:** `689c839` (Ensemble ML PR-01)
- **Code Proof:**
  - 17 Features: 8 URL features + 9 linguistic/structural features.
  - Dataset Size: `len(y) = 1000` (500 phishing + 500 legitimate generated by `_generate_synthetic_dataset()`).
  - Split: `train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)` $\rightarrow$ 800 train / 200 test.
  - Reproducibility Seed: `random_state=42` across train/test split, cross-validation, Random Forest, and XGBoost.

### Claim 8: VirusTotal: 15s Pacing, Max 2 Links, 4 req/min; Pending Normalization /0.85
- **Status:** **`MATCH`**
- **File & Lines:** `aegis-backend/modules/link_scanner.py:38–52, 90–120, 240–260`; `aegis-backend/modules/meta_classifier.py:28, 70–75`
- **Commits:** `8e9ce12` (VT link scanner), `d990bdd` (preliminary normalization)
- **Code Proof:**
  - Capping: `MAX_LINKS_PER_EMAIL: int = 2`.
  - Pacing: `DEFAULT_MIN_REQUEST_INTERVAL: float = 15.0` backed by `_pacing_lock: asyncio.Lock()`.
  - Rate Limit: Guarantees $\le 4$ requests/minute free-tier compliance.
  - Preliminary Normalization:
    ```python
    ACTIVE_PRELIMINARY_WEIGHT_SUM: float = WEIGHT_HEURISTIC + WEIGHT_NLP + WEIGHT_BEHAVIORAL # 0.85
    raw_score = (0.25 * s_h + 0.45 * s_nlp + 0.15 * s_b) / ACTIVE_PRELIMINARY_WEIGHT_SUM
    ```

### Claim 9: 300ms Debounce; 2s AbortController; Cache 100 Entries, 7-Day TTL
- **Status:** **`MATCH`**
- **File & Lines:** `aegis-extension/content_script.js:34, 110–125`; `aegis-extension/background.js:22–24, 130–165, 230–260`
- **Commits:** `dfa2265` (background bridge & LRU cache), `fd5080e` (debounced content script)
- **Code Proof:**
  - Debounce: `var DEBOUNCE_DELAY_MS = 300;` on Gmail DOM `MutationObserver`.
  - AbortController: `NETWORK_TIMEOUT_MS: 2000` via `fetchWithTimeout()` using `new AbortController()`.
  - Cache: `MAX_CACHE_ENTRIES: 100`, `CACHE_TTL_MS: 7 * 24 * 60 * 60 * 1000` (7 days) with LRU eviction.

### Claim 10: Presets: Conservative 35/65, Standard 45/75, Aggressive 55/85
- **Status:** **`MATCH`**
- **File & Lines:** `aegis-extension/dashboard/dashboard.html:193–216`; `aegis-extension/dashboard/dashboard.js:514–519`
- **Commit:** `a824a4e` (Milestone I-12 / PR-12)
- **Code Proof:**
  ```javascript
  const presetBtns = [
    { btn: qs('preset-conservative'), warn: 35, crit: 65 },
    { btn: qs('preset-standard'),     warn: 45, crit: 75 },
    { btn: qs('preset-aggressive'),   warn: 55, crit: 85 },
  ];
  ```

### Claim 11: PII Scrubber Covers Body Only; Subject, Sender, Links Unscrubbed
- **Status:** **`MATCH` (Nuanced Implementation Verified)**
- **File & Lines:** `aegis-extension/pii_scrubber.js:150–175`; `aegis-extension/content_script.js:285–305`; `aegis-backend/routes/analyze.py:99–115`
- **Commit:** `273142d` (PII Scrubber PR-06)
- **Code Proof:**
  In `pii_scrubber.js:scrubEmailPayload()`, `bodyResult = scrubText(payload.bodyText)` directly overwrites `payload.bodyText` with `[EMAIL]`, `[PHONE]`, `[CARD_NUMBER]`, `[SSN]`, `[NAME]`.
  In contrast:
  - `payload.senderEmail` and `payload.senderName` are passed through intact for domain and whitelist checks.
  - `payload.links` are passed through unscrubbed for Layer 4 URL inspection.
  - `payload.subject` is passed through unscrubbed (a scrubbed copy is stored in unused field `scrubbedSubject`).
  Thus, in network transmission and backend scoring, only body content is sanitized.

### Claim 12: Whitelist: Two Triggers (Display-Name Spoofing; Auth Failure); Null Auth -> Safe 5
- **Status:** **`MATCH`**
- **File & Lines:** `aegis-extension/whitelist/whitelist.js:70–245`
- **Commit:** `25af4bf` (Milestone 3.3 Whitelist Engine)
- **Code Proof:**
  - Trigger 1 (Display-Name Spoofing): Display name matches protected identity but sender domain differs $\rightarrow$ `revoked: true, score: 95, Critical`.
  - Trigger 2 (Auth Failure): Sender matches whitelist but `spfPass === false || dkimPass === false` $\rightarrow$ `revoked: true, score: 95, Critical`.
  - Clean Match: Whitelist match where auth is NOT explicitly false (i.e., passed or `null`/`undefined`) $\rightarrow$ `whitelisted: true, score: 5, Safe`.

### Claim 13: Offline Fallback: Rules in local_heuristics.js + Behavioral Score; Shows Score and Tier
- **Status:** **`MATCH`**
- **File & Lines:** `aegis-extension/background.js:330–355`; `aegis-extension/overlay/overlay.js:220–250, 480–525`; `aegis-extension/local_heuristics.js:478–535`
- **Commits:** `4e77889` (local heuristics), `a6925ff` (degraded mode PR-10)
- **Code Proof:**
  When network times out (>2.0s) or backend is down, `background.js` returns `_source: 'offline_fallback'`. `overlay.js` intercepts this and executes `window.AegisLocalHeuristics.evaluate()`, combining client-side rules with `emailContext.behavioralScore`. Displays computed score, categorical risk tier, and the "Offline Heuristic Mode" banner.

### Claim 14: Backend Stores State Only in Memory (_in_flight_scans, _analysis_store, _detection_log, _feedback_log); No Database
- **Status:** **`MATCH`**
- **File & Lines:** `aegis-backend/routes/analyze.py:58, 61, 818, 822, 988–994`; `aegis-backend/main.py:1–80`
- **Commit:** `8947afe` (Milestone 2.5), `7022a57` (feedback loop)
- **Code Proof:**
  ```python
  _in_flight_scans: Dict[str, Dict[str, Any]] = {}  # Line 58
  _analysis_store: Dict[str, Dict[str, Any]] = {}   # Line 61
  _detection_log: list[Dict[str, Any]] = []         # Line 818 (capped at 1000)
  _feedback_log: list[Dict[str, Any]] = []          # Line 822
  ```
  `clear_analysis_store()` wipes all four. Zero database imports (`sqlite3`, `psycopg2`, `SQLAlchemy`, etc.) exist anywhere in `aegis-backend`.

### Claim 15: Phase C: Dataset SHA-256 e278c600..., 50/50 TP/TN, Accuracy 100%, Avg Latency 91.93 ms
- **Status:** **`MATCH`**
- **File & Lines:** `aegis-backend/data/test_dataset.csv`; `evidence/E-08_phishing-corpus-metrics/E-08_phishing-corpus-metrics_report_20261108_0c541f5.json`
- **Commits:** `8c42233` (dataset freeze), `0c541f5` (Phase C benchmark execution)
- **Data & Metric Proof:**
  - Dataset SHA-256: `e278c6004a02e2935d83895d5e8242fcd8df50bc9b46641a10dc9ac6721f9254`.
  - Composition: 50 Phishing (`1`), 50 Legitimate (`0`). Total $N = 100$.
  - Accuracy: `100.00%` (Neutral Auth, TP=50, TN=50).
  - Latency: Average = `91.93 ms` (`latency_avg_ms: 91.93`, median: `91.13 ms`).

### Claim 16: Unit Tests: Count and Result of the Suite (Paper Says 45/45 Behavioral)
- **Status:** **`MATCH`**
- **File & Execution:** `aegis-extension/tests/test_behavioral_baseline.js`; `scratch/run_all_tests.py`
- **Verification Proof:**
  Direct execution of `node aegis-extension/tests/test_behavioral_baseline.js` yields:
  ```
  Behavioral Baseline Results: 45 passed, 0 failed.
  Exit Code: 0
  ```
  The full repository test suite contains:
  - Extension unit tests: 103 passed, 0 failed (Behavioral: 45, Whitelist: 18, Auth: 6, Local heuristics: 15, PII scrubber: 14, Attachment hashes: 5).
  - Backend unittest suite: 39 passed, 0 failed (Meta-classifier: 12, Attachment/VT: 14, Pipeline: 13).

---

## 4. OVERCLAIM SWEEP (14 TERMS AUDITED ACROSS DOCUMENTATION & UI)

Every documentation file, comment, UI string, and manifest in the repository was swept for obsolete or unsupported marketing claims.

| Term Audited | Total Hits Found | Locations & Context | Suggested Honest Replacement |
|---|:---:|---|---|
| **"real-time protection"** | **0** | None found across repository. | Clean (already removed in prior commits). |
| **"ongoing training"** | **0** | None found across repository. | Clean (already removed in prior commits). |
| **"deployment-ready"** | **0** | None found across repository. | Clean (already removed in prior commits). |
| **"production-ready"** | **0** | None found across repository. | Clean (already removed in prior commits). |
| **"97.5"** | **1** | `AGENT_LOG.md:156` (historical audit log documenting removal). | Historical log entry only; no action needed. |
| **"96.0"** | **5** | `AUDIT_ROUND5.md:128,129,178` (empirical Nazario recall at $T=25$). | Honest metric context: cite as *empirical Nazario test recall at calibrated cutoff 25*. |
| **"93.0"** | **4** | `AGENT_LOG.md:149`, `AUDIT_ROUND5.md:110` (historical raw benchmark accuracy). | Cite as *historical preliminary accuracy on early uncalibrated dataset*. |
| **"86.0"** | **4** | `AGENT_LOG.md:107,149`, `AUDIT_FOR_MANUSCRIPT.md:407` (historical benchmark recall). | Honest context: cite as *historical uncalibrated recall prior to Layer 1 augmentation*. |
| **"99%"** | **3** | `AUDIT_ROUND5.md:110,111` (upper Wilson CI bound: 99.5%). | Honest statistical notation: cite as *95% Wilson confidence interval [93.0%, 99.5%]*. |
| **"zero-day"** | **4** | `LIVE_DEMONSTRATION_GUIDE.md:142`, `docs/01-5_week_prototype_development_plan.md:444` | Replace with *novel, previously unencountered phishing lures without explicit keyword cues*. |
| **"quarantine"** | **8** | `E-11_auth-inference-code_refs_20261107_91e1e8d.md:17,134`, `E-29_fr01-fr08-wording_refs_20261107_a482063.md:35` | Replace with *advisory visual risk notification (no native mailbox quarantine capability)*. |
| **"Gmail API"** | **5** | `E-25_citation-check_sources_20261107_a482063.md:28`, `E-29_fr01-fr08-wording_refs_20261107_a482063.md:56` | Replace with *client-side DOM extraction via Chrome Extension Content Script (no Gmail API access)*. |
| **"DMARC"** | **18** | `docs/01-5_week_prototype_development_plan.md:293`, `E-44_explainability-protocol/STUDY_PROTOCOL.md:22` | Replace with *SPF and DKIM header verification (DMARC is not parsed from Gmail DOM)*. |
| **"SUS"** | **34** | `implementation_plan.md:40,315,346`, `E-44_explainability-protocol/*.md` | Replace with *System Usability Scale (Brooke, 1996) 10-item standardized questionnaire*. |
| **"retrain"** | **1** | `evidence/E-21_model-provenance/E-21_model-provenance_20261107_320e9b3.md:35` | Text already states honestly: *"No real-time retraining or online continuous learning is active in deployment."* |

---

## 5. EVIDENCE MANIFEST SUMMARY & INTEGRITY HASHES

A complete master evidence manifest mapping all evidence identifiers from `E-01` through `E-45` has been generated and written to `evidence/MANIFEST.md`.

### 5.1 Special Status Disclosures
1. **`E-05` and `E-06` Formally WITHDRAWN:**
   - Both early benchmark runs (`E-05_placeholder-benchmark_20261023_8c42233.json` and `E-06_full-pipeline-rerun_20261107_160d746.json`) were executed before the runtime model-loaded guard was implemented, resulting in unprimed ONNX session states. Formally marked **`WITHDRAWN`**.
2. **Round 3 Fallback Calibration SUPERSEDED:**
   - `evidence/E-39_independent-corpus/E-39_train_calibration_report.json` initial run ran before `warm_up_nlp()` was integrated into the harness. Marked **`SUPERSEDED`** by the rerun executed under commit `19affee`.
3. **Pure Nazario Test Evaluation CONTAMINATED:**
   - `evidence/E-39_independent-corpus/nazario_only_eval.json` is marked **`CONTAMINATED`** because 10 of the 25 Nazario positive test samples (40.0%) overlap with `E-39_dataset_train_200.csv` due to independent random sampling without deduplication against the training split.
4. **All Evidence Preserved:**
   - Zero evidence files were deleted. All historical artifacts remain intact in version control and working directory.

### 5.2 Checksum Files Generated
- **`evidence/SHA256SUMS`**: Contains SHA-256 digests for all 98 files in `evidence/`.
- **`data/SHA256SUMS`**: Contains SHA-256 digests for all primary evaluation datasets and ONNX model artifacts:
  - `e278c6004a02e2935d83895d5e8242fcd8df50bc9b46641a10dc9ac6721f9254  aegis-backend/data/test_dataset.csv`
  - `e55b074469621c8db1d4c62cb72750951350734b1e41fcddbf19a99107897b63  aegis-backend/data/vt_seed_cache.json`
  - `e9fabc5209258a5d13727ff8a08a4575845012d5df9582d38dbc486148bfdd4f  aegis-backend/data/vt_file_seed_cache.json`
  - `361ebc80a1aa7f48778ad007abed802f93fc807ffbd741e8661cf3837c200db0  aegis-backend/models/phishing_distilbert/model.onnx`
  - `c7b0ad4a6309973a228f07bc7aeb6c913bcc122e5bc1cefa97d856a1770c3c9f  evidence/E-39_independent-corpus/E-39_dataset_full_250.csv`
  - `1a99b4e1ce1ca27e25822e5a7a1ce323094a26a61d0b855ec6c40e4563aad28e  evidence/E-39_independent-corpus/E-39_dataset_train_200.csv`
  - `d7458d308e97c992fa42dcb0b7fd82bbafb2d60cc8a747be85656441b9bb927c  evidence/E-39_independent-corpus/E-39_dataset_test_50.csv`
  - `a8c31320a4438e20dcd37d2de92219e25df525927d4a36b352bca4dbf4257217  evidence/E-39_independent-corpus/E-39_nazario_pure_phishing_125.csv`

---

## 6. REPRODUCIBILITY GUIDE SUMMARY (`REPRODUCE.md`)

`REPRODUCE.md` has been authored in the repository root providing exhaustive replication instructions. Key elements:
- **Environment:** Python 3.14.7 / 3.11-slim, Node.js v18+, CPU inference via ONNX Runtime (<140MB RSS).
- **Exact Pinned Dependencies:** Pinned versions for all 14 libraries listed.
- **Deterministic Commands:**
  - Behavioral Unit Tests: `node aegis-extension/tests/test_behavioral_baseline.js`
  - Phase C Full Pipeline (E-08): `python tools/run_phase_c_evaluations.py --commit 0c541f5` (Seed 42)
  - Warning Cut-off Calibration: `python tools/calibrate_warning_cutoff.py` (Seed 42)
  - Multi-Set Benchmark: `python tools/run_round2_evaluations.py --commit 11564ab` (Seed 42)
- **Non-Reproducible Disclosures:**
  - Live VirusTotal API queries (rate limits, dynamic threat updates, private API key).
  - Live Render latency measurements (cloud idle spin-up, network distance).
  - LLM-authored email generation (commercial API drift, safety guardrails).
  - UAT participant survey data (human empirical subjects).

---

## 7. FINAL SUBMISSION STAGING PLAN (PENDING APPROVAL)

Per the strict read-only mandate of this pass:
> *"No force-push, rebase, or history rewrite without my written approval. If unsure, report it instead of fixing it... THEN, AND ONLY THEN, with my approval of the report: stage commits in logical groups on branch final-submission; update .gitignore; commit; tag v1.0-capstone-submission."*

### Proposed Staging Groups (For Execution Upon Your Approval):
1. **Redact Sensitive File:**
   - Redact literal 64-character VirusTotal key in `evidence/AUDIT_ROUND4.md:250, 271` to `[MASKED_VT_KEY]`.
2. **Update `.gitignore`:**
   - Add `data/external_corpora/`, `aegis-backend/results/`, `scratch/`, `extracted_media/`, `final docs/`, and `*.xlsx` course management sheets to `.gitignore`.
3. **Branch Creation:**
   - Create and checkout branch `final-submission`.
4. **Grouped Commits:**
   - **Commit 1 (`docs(submission)`):** `REPRODUCE.md`, `AI_USE.md`, `LIVE_DEMONSTRATION_GUIDE.md`, `AGENT_LOG.md`, `FINAL_INTEGRITY_REPORT.md`.
   - **Commit 2 (`eval(tools)`):** Updated evaluation scripts in `tools/` and `aegis-backend/scripts/measure_live_api.py`.
   - **Commit 3 (`evidence(audit)`):** Master manifest `evidence/MANIFEST.md`, `evidence/SHA256SUMS`, `data/SHA256SUMS`, audit reports `AUDIT_ROUND2.md` through `AUDIT_ROUND5.md`, and stamped Phase C/Round 2 evidence files.
5. **Annotated Tagging:**
   - Apply lightweight/annotated tag: `git tag -a v1.0-capstone-submission -m "Aegis Capstone Final Submission v1.0"`.
   - Print tag commit hash and verification summary.

---

## 8. AI-USE RECORD SUMMARY (`AI_USE.md`)

`AI_USE.md` has been authored in the repository root providing full disclosure of AI tools strictly grounded in Git history and verifiable repository files:
- **AI Coding Assistants (Interactive Pair Programming):** Proponent self-disclosure for code structure, component layouts, and FastAPI routes. Specific model versions and session IDs are designated as **UNKNOWN in Git history** (commit metadata records standard developer commits under `j4ffyy`).
- **Autonomous Evaluation & Auditing Agent (Antigravity):** Documented in repository dev logs (`AGENT_LOG.md`) for benchmark harness execution, model-loaded verification, manifest generation, and integrity audits.
- **Commercial LLM Session (External Corpus Generation):** Generation of 60 synthetic corporate emails without keyword cues for `evidence/E-43_llm-authored-eval/` (model name as reported and not verified; prompts documented in `E-43_llm_generation_prompts.json`).
- **In-Editor Autocomplete (GitHub Copilot / Cursor):** Documented as **UNKNOWN** (cannot be confirmed or disproven from Git commit metadata).
- **Defensive ML Components (Evaluated Artifacts):** Pre-trained DistilBERT ONNX (`phishing_distilbert_onnx_4cls`) and Scikit-Learn/XGBoost ensemble classifiers clearly delineated as pipeline components rather than generative assistants.

