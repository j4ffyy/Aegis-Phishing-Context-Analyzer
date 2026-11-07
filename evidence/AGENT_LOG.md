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


