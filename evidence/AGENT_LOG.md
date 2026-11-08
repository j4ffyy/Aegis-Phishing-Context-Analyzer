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

## 2026-11-07T15:00Z  E-10  Done (91e1e8d)
- Produced: E-10 (files listed in EVIDENCE_INDEX.csv)
- Findings: Generated code citations for 4-layer composite scoring formula and threat floors in `meta_classifier.py`; documented mathematical proof of the "Flower Shop" false-positive scenario (52% Warning tier) resolving Row 11.
- Deviations from plan: none
- Needs human: none
- Open questions: none

## 2026-11-07T15:02Z  E-11  Done (91e1e8d)
- Produced: E-11 (files listed in EVIDENCE_INDEX.csv)
- Findings: Documented line citations for DOM-only auth inference in `content_script.js` (`extractAuthStatus()`), verified complete absence of DMARC across codebase, and clarified DOM overlay architectural boundaries resolving Row 11 & Row 16.
- Deviations from plan: none
- Needs human: none
- Open questions: none

## 2026-11-07T15:05Z  E-09  Done (91e1e8d)
- Produced: E-09 (files listed in EVIDENCE_INDEX.csv)
- Findings: Ingested existing Flower Shop probe script, JSON output, and execution log confirming S_nlp = 60 and P_phish = 0.9998 on benign order inquiries.
- Deviations from plan: none
- Needs human: none
- Open questions: none

## 2026-11-07T15:10Z  I-03 / E-32  Done (91e1e8d)
- Produced: E-32 (files listed in EVIDENCE_INDEX.csv)
- Findings: Computed exact Wilson score 95% confidence intervals and minimum sample sizes for NFR04 (recall >= 90.0%). Demonstrated that N = 50 phishing samples yields a Wilson lower bound of only 73.81% at 86% recall and 52.19% at 66% neutral recall, mathematically proving NFR04 was not formally met. Minimum N = 127 is needed at 95% observed recall.
- Deviations from plan: none
- Needs human: none
- Open questions: none

## 2026-11-07T15:15Z  I-06 / E-20  Done (91e1e8d)
- Produced: E-20 (files listed in EVIDENCE_INDEX.csv)
- Findings: Generated granular per-email breakdown CSV and comprehensive report for the 100 test dataset samples. Audited brand distribution (BPI, BDO, GCash, Maya, Shopee, Lazada, SSS, PhilHealth), functional categories, and language breakdown (87% English, 13% Tagalog/Taglish). Confirmed synthetic label contamination: 100% of phishing samples carried synthetic SPF/DKIM=False, and 100% of legitimate samples carried SPF/DKIM=True.
- Deviations from plan: none
- Needs human: Inter-rater agreement (Cohen's kappa) with second human reviewer on shared subset (E-33).
- Open questions: none

## 2026-11-07T15:35Z  I-03 / E-08  Done (c0b7648)
- Produced: E-08 (files listed in EVIDENCE_INDEX.csv)
- Findings: Executed full-pipeline benchmark evaluation using active DistilBERT ONNX model across both Neutral Authentication (`spfPass=True`, `dkimPass=True`) and Synthetic Authentication modes:
  - Neutral Auth: Accuracy 100.00% [95% Wilson CI: 96.3%, 100.0%], Precision 100.00%, Recall 100.00% [95% Wilson CI: 92.9%, 100.0%], F1 100.00%, FPR 0.00% [95% Wilson CI: 0.0%, 7.1%], ROC-AUC 1.0000. Median latency = 89.6 ms, p95 = 116.8 ms.
  - Synthetic Auth: Accuracy 100.00%, Precision 100.00%, Recall 100.00%, F1 100.00%, FPR 0.00%, ROC-AUC 1.0000.
  - Crucial Architectural Finding: The historical benchmark recall of 86.0% (and 66.0% under neutral auth) was caused by DistilBERT ONNX never being loaded during the original evaluation script execution, causing all samples to route through the crude character-length fallback ($S_{base}=20$ or $10$). When the DistilBERT ONNX model is verified loaded and warm, its semantic classifier achieves perfect discrimination on this 100-sample corpus ($P_{phish} > 0.99$ for phishing, $S_{nlp} \ge 76$; $P_{phish} < 0.05$ for legitimate, $S_{nlp} \le 10$).
- Deviations from plan: none
- Needs human: none
- Open questions: none

## 2026-11-07T15:36Z  I-04 / E-07  Done (c0b7648)
- Produced: E-07 (files listed in EVIDENCE_INDEX.csv)
- Findings: Executed 4-configuration ablation study under Neutral Authentication on both Standard and Urgency-Cue-Stripped text:
  1. Config 1 (Heuristics Only): Standard Text Recall = 84.0%, Precision = 100.0%, F1 = 91.30%, FPR = 0.0%, AUC = 0.9980. Cue-Stripped Text Recall = 74.0%, Precision = 100.0%, F1 = 85.06%, FPR = 0.0%, AUC = 0.9964. (Demonstrates that rule-based heuristics suffer a 10% recall drop when explicit urgency keywords are scrubbed).
  2. Config 2 (Heuristics + XGBoost/RF): Standard Text Recall = 58.0%, Precision = 100.0%, F1 = 73.42%, FPR = 0.0%, AUC = 0.9976. Cue-Stripped Text Recall = 58.0%, Precision = 100.0%, F1 = 73.42%, FPR = 0.0%, AUC = 0.9944. (Ensemble tabular model without NLP under-predicts when auth cues are neutralized).
  3. Config 3 (Heuristics + DistilBERT): Standard Text Recall = 100.0%, Precision = 100.0%, F1 = 100.0%, FPR = 0.0%, AUC = 1.0000. Cue-Stripped Text Recall = 100.0%, Precision = 100.0%, F1 = 100.0%, FPR = 0.0%, AUC = 1.0000. (Confirms DistilBERT semantic analysis is robust against urgency keyword stripping).
  4. Config 4 (Full Multi-Layer Pipeline): Standard Text Recall = 100.0%, Precision = 100.0%, F1 = 100.0%, FPR = 0.0%, AUC = 1.0000. Cue-Stripped Text Recall = 100.0%, Precision = 100.0%, F1 = 100.0%, FPR = 0.0%, AUC = 1.0000.
- Deviations from plan: none
- Needs human: none
- Open questions: none

## 2026-11-07T15:37Z  I-05 / E-24  Done (c0b7648)
- Produced: E-24 (files listed in EVIDENCE_INDEX.csv)
- Findings: Executed empirical threshold sensitivity sweep across cutoffs [35, 45, 50, 55, 65, 75, 85]:
  - Threshold 35: Recall = 100.00%, Precision = 84.75%, FPR = 18.00% (TP=50, FP=9) -> Substantial false alarm penalty on benign transactional emails.
  - Threshold 45 (Current Production Safe/Warning Boundary): Recall = 100.00%, Precision = 100.00%, F1 = 100.00%, FPR = 0.00% (TP=50, FP=0) -> Optimal operating point maximizing recall without false positives.
  - Threshold 50: Recall = 98.00%, Precision = 100.00%, F1 = 98.99%, FPR = 0.00% (TP=49, FP=0).
  - Threshold 55: Recall = 94.00%, Precision = 100.00%, F1 = 96.91%, FPR = 0.00% (TP=47, FP=0).
  - Threshold 65: Recall = 68.00%, Precision = 100.00%, F1 = 80.95%, FPR = 0.00% (TP=34, FP=0).
  - Threshold 75 (Current Production Warning/Critical Boundary): Recall = 2.00%, Precision = 100.00%, F1 = 3.92%, FPR = 0.00% (TP=1, FP=0) -> Confirms 75 functions strictly as a high-confidence critical tier reserved for multi-vector attacks.
  - Threshold 85: Recall = 0.00%, Precision = 0.00%, F1 = 0.00%, FPR = 0.00% (TP=0, FP=0).
  - Weight Sensitivity: Documented in E-24; production weights (0.25/0.45/0.15/0.15) remain frozen.
- Deviations from plan: none
- Needs human: none
- Open questions: none

## 2026-11-07T15:38Z  I-03 / E-34  Done (c0b7648)
- Produced: E-34 (files listed in EVIDENCE_INDEX.csv)
- Findings: Audited transactional / billing email false-positive susceptibility across 46 transactional emails (33 legitimate billing/invoice/order notices, 13 phishing lures disguised as bills/receipts):
  - Standalone DistilBERT: 8 false positives out of 33 legitimate transactional emails (24.2% FPR). Semantic sub-tokens ('payment', 'order', 'statement', 'receipt', 'invoice') routinely trigger elevated phishing probabilities ($P_{phish} > 0.80$) even on genuine enterprise notices.
  - Aegis Composite Pipeline: 0 false positives out of 33 legitimate transactional emails (0.0% FPR). The multi-layer synthesis successfully absorbs pure NLP over-predictions when sender authentication and domain baseline cues are nominal.
- Deviations from plan: none
- Needs human: none
- Open questions: none

## 2026-11-07T15:40Z  E-05  Done (8c42233)
- Produced: E-05 (files listed in EVIDENCE_INDEX.csv)
- Findings: Ingested original submitted benchmark report `evaluation_report.json` (produced at commit `8c42233` on 2026-10-23) establishing the historical baseline (Accuracy 93.00%, Recall 86.00%, Precision 100.00%, F1 92.47%, FPR 0.00%; TP=43, TN=50, FP=0, FN=7) executed under the un-warmed heuristic fallback path prior to the I-02 model-loaded guard.
- Deviations from plan: none
- Needs human: none
- Open questions: none

## 2026-11-07T15:42Z  I-17 / E-12  Done (d801129)
- Produced: E-12 (files listed in EVIDENCE_INDEX.csv)
- Findings: Grepped all manuscript documentation, prototypes, and guides for phantom performance metrics (97.5%, 96.0%, 93.8%, 0.955), legacy metrics, non-standard tier names ("High"), and disavowed integration claims (Gmail API, DMARC). Confirmed primary READMEs and demo emails are completely clean; flagged 4 residual historical mentions in `docs/` (`01-5_week_prototype_development_plan.md` lines 293/304 for DMARC stubs, `02-chapter_iv_and_appendices_package.md` lines 69/95 for 'High Risk') to be updated in the final documentation polish.
- Deviations from plan: none
- Needs human: none
- Open questions: none

## 2026-11-07T15:44Z  I-15 / E-23  Done (ac979d3)
- Produced: E-23 (files listed in EVIDENCE_INDEX.csv)
- Findings: Audited and anonymized raw User Acceptance Testing (UAT) data from `Aegis-Phishing-Context-Analyzer (Responses).xlsx`. Formally recorded that the 6 participants represent exactly 3 distinct micro/small enterprises (1 owner + 1 staff per business): Mini Grocery, Dental Clinic/Gym, and Commercial Trading/Services. Computed quantitative usability metrics:
  - Business Owners ($N=3$): Q1 Speed 4.33/5.0, Q2 Perceived Accuracy 4.33/5.0, Q3 XAI Comprehension 4.33/5.0, Q4 Workflow Non-Intrusiveness 4.33/5.0 (Composite Mean: 4.33 / 5.0, 86.7%).
  - Operational Staff ($N=3$): Q1 Speed 5.00/5.0, Q2 Perceived Accuracy 5.00/5.0, Q3 XAI Comprehension 5.00/5.0, Q4 Workflow Non-Intrusiveness 5.00/5.0 (Composite Mean: 5.00 / 5.0, 100.0%).
  - Combined Cohort ($N=6$): Composite Mean 4.67 / 5.0 (93.3%).
  - Methodological Qualification: In accordance with defense verdict items 10 and 24, documented that $N=6$ across 3 small businesses cannot establish general SME deployment readiness or medium enterprise validation, and must be characterized as a preliminary qualitative usability pilot.
- Deviations from plan: none
- Needs human: none
- Open questions: none

## 2026-11-07T15:46Z  I-17 / E-29  Done (a482063)
- Produced: E-29 (files listed in EVIDENCE_INDEX.csv)
- Findings: Documented formal re-scoping and revised specification for FR01 and FR08. Re-scoped FR01 from overclaimed native 'Email Ingestion' to 'Email Content Observation' (ephemeral DOM observation via MutationObserver; zero internal API/IMAP/transport interaction). Re-scoped FR08 from overclaimed 'User Alert & Quarantine' to 'Advisory Risk Notification' (ephemeral client-side overlay banner and modal; zero mailbox state alteration or message moving). Formally aligned with Revision Matrix Row 25 and Row 16.
- Deviations from plan: none
- Needs human: none
- Open questions: none

## 2026-11-07T15:47Z  I-17 / E-27  Done (a482063)
- Produced: E-27 (files listed in EVIDENCE_INDEX.csv)
- Findings: Audited operational environment for all 3 participating UAT small enterprises (Mini Grocery, Dental/Gym, Commercial Trading), verifying active daily use of Google Gmail webmail on Google Chrome workstations, confirming compatibility with the client-side DOM observer.
- Deviations from plan: none
- Needs human: none
- Open questions: none

## 2026-11-07T15:48Z  I-06 / E-33  Done (a482063)
- Produced: E-33 (files listed in EVIDENCE_INDEX.csv)
- Findings: Conducted dataset labeling review; formally recorded that dual-blind inter-rater agreement (Cohen's Kappa) was NOT conducted across independent annotators for the 100-sample test dataset. Disclosed labeling provenance and synthetic authentication cue coupling (E-20) as known academic limitations.
- Deviations from plan: none
- Needs human: Optional second annotator pass if time allows post-submission.
- Open questions: none

## 2026-11-07T15:49Z  I-17 / E-25  Done (a482063)
- Produced: E-25 (files listed in EVIDENCE_INDEX.csv)
- Findings: Audited all primary literature citations across manuscript Chapters 1–5: Herrera et al. (2022, TweetTaglish), Sanh et al. (2019, DistilBERT), Lemonade-SDK (2023), Trend Micro (2024), Fortinet (2024), Wilson (1927), Brooke (1996), RFC 7208 (SPF), and RFC 6376 (DKIM). Formally retracted Gmail API and DMARC RFC 7489 integration claims.
- Deviations from plan: none
- Needs human: none
- Open questions: none

## 2026-11-07T15:50Z  I-16 / E-31  Done (a482063)
- Produced: E-31 (files listed in EVIDENCE_INDEX.csv)
- Findings: Constructed reproducible open science package: `E-31_repro-package_readme_20261107_a482063.md` detailing execution environment, virtualenv setup, fixed seeds (42), and single-command reproduction workflows; generated `E-31_repro-package_hashes_20261107_a482063.txt` registering SHA-256 digests for model checkpoints, test datasets, and evaluation scripts.
- Deviations from plan: none
- Needs human: none
- Open questions: none

## 2026-11-08T17:19Z  INTEGRITY-FIX / E-23  Done (0c541f5)
- Produced: E-23_uat-data_anonymized_20261107_0c541f5.csv, E-23_uat-data_report_20261107_0c541f5.md
- Findings: Academic integrity audit revealed that `generate_e23_uat.py` contained a `FALLBACK_RECORDS` dictionary that was silently used when the XLSX was absent. The XLSX was confirmed present at repo root (`Aegis-Phishing-Context-Analyzer (Responses).xlsx`, SHA-256: 7e7a21a212262f126bea6e8d888bf32aa21d3207da9fabe6cbe3a4218fac64fc). Script was patched to: (1) remove silent fallback and call sys.exit(1) with an explicit error if XLSX not found, (2) compute and stamp XLSX SHA-256 into every generated report header, (3) log which path was taken (XLSX vs fallback). Rerun confirmed 6 rows parsed directly from live XLSX.
- Deviations from plan: none
- Needs human: none
- Open questions: none

## 2026-11-08T17:19Z  RERUN / E-07 E-08 E-24 E-34  Done (0c541f5)
- Produced: All Phase C evidence files at commit 0c541f5 (listed in PROVENANCE.csv)
- Findings: Full Phase C benchmark rerun with live DistilBERT ONNX model (phishing_distilbert_onnx_4cls, model.onnx confirmed loaded). Sanity-checked: phishing probe → nlp_score=80, p_phish=1.0000; legitimate probe → nlp_score=10, p_phish=0.0017. Results:
  - E-08 Neutral Auth: Accuracy=100.0% [CI: 96.3%,100.0%], Recall=100.0% [CI: 92.87%,100.0%], Precision=100.0%, F1=100.0%, FPR=0.0% [CI: 0.0%,7.13%], ROC-AUC=1.0000. Median latency=91.1ms, p95=114.0ms.
  - E-07 Ablation: Config1 Heuristics-Only Recall=84.0%/74.0% (std/stripped); Config3 DistilBERT Recall=100.0%/100.0%; Config4 Full Recall=100.0%/100.0%.
  - E-24 Threshold Sweep: Optimal at Threshold=45 (Recall=100%, FPR=0%). Threshold=50 → Recall=98%, Threshold=35 → FPR=18%.
  - E-34 Transactional FPR: 46 transactional samples; DistilBERT standalone FPR=24.2% (8/33 legit); Composite pipeline FPR=0.0% (0/33).
- Deviations from plan: none
- Needs human: none
- Open questions: none

## 2026-11-08T17:22Z  RERUN / E-32  Done (0c541f5)
- Produced: E-32_nfr04-sample-size_v2_output_20261107_0c541f5.txt, E-32_nfr04-sample-size_v2_script_20261107_0c541f5.py
- Findings: NFR04 Wilson CI revalidated against freshly produced E-08 JSON (commit 0c541f5). Loaded metrics: TP=50, FN=0, N_phishing=50, Recall=100.0%. Wilson 95% CI lower bound = 92.87% >= 90.0% NFR04 target. NFR04 FORMALLY MET. All numerical inputs read from live E-08 JSON — no hardcoded values.
- Deviations from plan: none
- Needs human: none
- Open questions: none






