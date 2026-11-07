# AGENT_LOG.md — Aegis Evidence Work Log
> Append only. Format: ## <ISO8601Z>  <I-xx>  <Status> (<commit7>)

## 2026-11-07T13:15Z  I-02  Done (160d746)
- Produced: E-06 (files listed in EVIDENCE_INDEX.csv)
- Findings: Model-loaded guard implemented in /health and evaluate_models.py; DistilBERT ONNX (phishing_distilbert_onnx_4cls) is loaded and verified; benchmark aborts if model_loaded=False.
- Deviations from plan: none
- Needs human: none
- Open questions: none

## 2026-11-07T13:17Z  I-13  Done (fca8158)
- Produced: E-36 (files listed in EVIDENCE_INDEX.csv)
- Findings: Grep audit of 57 source files confirmed: DMARC absent from extension and backend runtime (1 reference in docx script); 'High' absent from runtime tier logic; URL masking 0 matches; Gmail API 0 matches.
- Deviations from plan: none
- Needs human: none
- Open questions: none

## 2026-11-07T13:18Z  I-07  Done (320e9b3)
- Produced: E-21 (files listed in EVIDENCE_INDEX.csv)
- Findings: DistilBERT ONNX checkpoint documented: 6-layer 255.5 MB ONNX (SHA256: 361ebc80...), 4 classes, P_phish = P(1)+P(3), 20% FPR on isolated transactional emails, English vocabulary limits Tagalog/Taglish.
- Deviations from plan: none
- Needs human: Confirm pre-training corpus lineage if historical archives are accessible; otherwise limitation note stands.
- Open questions: none

## 2026-11-07T13:22Z  I-09  Done (85e8e3a)
- Produced: E-03, E-04, E-28 (files listed in EVIDENCE_INDEX.csv)
- Findings: Full email body sent as scrubbed plain text (PII redacted via pii_scrubber.js); backend logs no request bodies; in-memory dicts (_in_flight_scans, _analysis_store, _detection_log, _feedback_log) are process-volatile and reset on restart.
- Deviations from plan: none
- Needs human: Render dashboard screenshot for region/settings (E-02, E-04 companion).
- Open questions: none

## 2026-11-07T13:56Z  I-10  Done (6a6ba94)
- Produced: E-19 (files listed in EVIDENCE_INDEX.csv)
- Findings: Scan trigger is debounced (300 ms) and deduplicated by composite signature (sender, subject, attachments, links, body); user interaction required via FAB when panel closed; VirusTotal outbound queries capped at 2 URLs and paced by >= 15.0s asyncio.Lock with triple local cache.
- Deviations from plan: none
- Needs human: none
- Open questions: none

## 2026-11-07T14:25Z  I-01  Done (799f152)
- Produced: E-14 (files listed in EVIDENCE_INDEX.csv)
- Findings: Fixed auth-state logic in `meta_classifier.py` and `routes/analyze.py`. When `spfPass` and `dkimPass` are both null (collapsed/indeterminate headers), Layer 1 displays neutral "Not verified: Authentication headers missing" (`fa-minus-circle`) in both the sidebar overlay and the Full Analysis Modal (`status-skip`, "Not verified"), preventing false "Pass" indicators without altering composite scoring or threshold floors. Verified across 13 unit/route tests in `test_auth_states.py` and 74 total backend tests.
- Deviations from plan: none
- Needs human: Capture live Gmail screenshots of the three auth states:
  1. `evidence/E-14_spf-dkim-drawer-states/E-14_spf-dkim-drawer-states_state-pass_YYYYMMDD_human.png` (verified domain, e.g. legitimate signed email)
  2. `evidence/E-14_spf-dkim-drawer-states/E-14_spf-dkim-drawer-states_state-fail_YYYYMMDD_human.png` (warning banner or failed SPF/DKIM)
  3. `evidence/E-14_spf-dkim-drawer-states/E-14_spf-dkim-drawer-states_state-null_YYYYMMDD_human.png` (collapsed/unverified headers showing "Not verified")
- Open questions: none

## 2026-11-07T14:36Z  I-12  Done (a824a4e)
- Produced: E-17 (files listed in EVIDENCE_INDEX.csv)
- Findings: Audited all three post-defense UI features and introduced missing guided presets:
  1. Two-tier XAI panel (plain-language summary card + expandable Advanced FAM modal): verified introduced in commits `bef94c6`, `fc0ea76`, `d990bdd`, and `326b02d`.
  2. VirusTotal reasons in XAI panel and threat indicators: verified in commits `8947afe`, `d990bdd`, and `56a8819`.
  3. Conservative / Standard / Aggressive presets with tooltips: raw sliders from commit `5357495` upgraded in `a824a4e` with 3 guided presets (Conservative 35%/65%, Standard 45%/75%, Aggressive 55%/85%) and contextual risk tooltips for non-technical users.
- Deviations from plan: none
- Needs human: Capture live UI screenshots for Annex A:
  1. `evidence/E-13_two-tier-xai-panel/E-13_two-tier-xai-panel_before_YYYYMMDD_human.png` & `_after_...png`
  2. `evidence/E-15_virustotal-reasons-panel/E-15_virustotal-reasons-panel_...png`
  3. `evidence/E-16_threshold-presets/E-16_threshold-presets_...png` (dashboard settings with preset buttons active)
- Open questions: none

## 2026-11-07T14:40Z  FREEZE  Done (eval-freeze)
- Tag: `eval-freeze`
- Target Commit: `f86cf64ca69545bdb84955ac9be4189f374a9d45`
- Status: Code frozen for Phase C evaluations. All Phase A setup items (A-0, manifest tooling) and Phase B fixes (I-01 auth display, I-02 model guard, I-07 model provenance, I-09 data audit, I-10 scan trigger audit, I-12 UI confirm/build & guided presets, I-13 string audit) completed and verified across 74 backend tests and 21 extension tests. No further code modifications permitted until evaluations conclude.




