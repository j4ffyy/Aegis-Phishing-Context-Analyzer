# Aegis Evidence Manifest (MANIFEST.md)

**Generated:** 2026-11-09T05:21:00Z  
**Commit Context:** `19affee1814c882d8b80390746995777453bc45e`  
**Scope:** Comprehensive mapping of all evidence identifiers (E-01 through E-45), file artifacts, creation commit provenance, SHA-256 digests, and validation status.

---

## Status Taxonomy
- **`VALID`**: Validated artifact generated under genuine, verified execution conditions with loaded model weights.
- **`WITHDRAWN`**: Formally retracted evidence due to execution condition non-compliance (e.g., model unprimed/unloaded at runtime).
- **`SUPERSEDED`**: Replaced by subsequent validated evaluation iterations or higher-fidelity measurements.
- **`CONTAMINATED`**: Disclosed data overlap between evaluation test split and historical training set.
- **`DROPPED / UNVERIFIED`**: Not utilized or consolidated into higher-order evidence items during revision rounds.

---

## Master Evidence Ledger (E-01 to E-45)

| E-ID | Canonical Slug | Primary File Path | Creation Commit | SHA-256 Digest | Status | One-Line Purpose / Description |
|:---:|---|---|:---:|---|:---:|---|
| **E-01** | `title-approval` | `N/A (Administrative institutional record)` | `n/a` | `n/a...` | **DROPPED / UNVERIFIED** | Capstone project title approval record from panel. |
| **E-02** | `render-region` | `N/A (Institutional cloud console record)` | `n/a` | `n/a...` | **DROPPED / UNVERIFIED** | Render.com deployment region console verification. |
| **E-03** | `backend-payload` | `evidence/E-03_backend-payload/E-03_backend-payload_refs_20261107_85e8e3a.md` | `6a6ba94` | `42d3ba792dbb7134...` | **VALID** | Audit citation verifying privacy-preserving email payload structure transmitted to backend. |
| **E-04** | `request-body-logging` | `evidence/E-04_request-body-logging/E-04_request-body-logging_refs_20261107_85e8e3a.md` | `6a6ba94` | `d40dde46b1032d5f...` | **VALID** | Verification of zero plaintext credential/body persistence in FastAPI server access logs. |
| **E-05** | `placeholder-benchmark` | `evidence/E-05_placeholder-benchmark/E-05_placeholder-benchmark_20261023_8c42233.json` | `74fc9af` | `8e10c93ae6314516...` | **WITHDRAWN** | WITHDRAWN: Initial placeholder benchmark run (DistilBERT ONNX model not primed in container). |
| **E-06** | `full-pipeline-rerun` | `evidence/E-06_full-pipeline-rerun/E-06_full-pipeline-rerun_20261107_160d746.json` | `74fc9af` | `ca2a73d6859d55ac...` | **WITHDRAWN** | WITHDRAWN: Rerun pipeline evaluation where model-loaded guard failed (model not loaded). |
| **E-07** | `ablation` | `evidence/E-07_ablation/E-07_ablation_summary_20261108_0c541f5.csv` | `0c541f5` | `b3cc915e57e13093...` | **VALID** | 4-layer ablation study evaluating combinatorial contribution of each defense layer. |
| **E-08** | `phishing-corpus-metrics` | `evidence/E-08_phishing-corpus-metrics/E-08_phishing-corpus-metrics_report_20261108_0c541f5.json` | `0c541f5` | `4afb47beb428e897...` | **VALID** | Benchmark metrics on 100-email test set under neutral and synthetic auth (100% acc, 91.93ms). |
| **E-09** | `flower-shop-probe` | `evidence/E-09_flower-shop-probe/E-09_flower-shop-probe_output_20261106_na.json` | `54a8720` | `1c2b7cfff6ffb9ab...` | **VALID** | Semantic sensitivity probe demonstrating low false-positive response on benign urgent shop copy. |
| **E-10** | `scoring-formula-code` | `evidence/E-10_scoring-formula-code/E-10_scoring-formula-code_refs_20261107_91e1e8d.md` | `54a8720` | `3fcb5583e4fbfc3e...` | **VALID** | Exact source code reference audit for composite scoring weights (0.25, 0.45, 0.15, 0.15). |
| **E-11** | `auth-inference-code` | `evidence/E-11_auth-inference-code/E-11_auth-inference-code_refs_20261107_91e1e8d.md` | `54a8720` | `674271eadf3e09ec...` | **VALID** | Exact source code reference audit for DOM SPF/DKIM extraction and 3-state auth display logic. |
| **E-12** | `manuscript-figure-audit` | `evidence/E-12_manuscript-figure-audit/E-12_manuscript-figure-audit_20261107_d801129.txt` | `d801129` | `e4957f9f77b49974...` | **VALID** | Comprehensive reconciliation script between manuscript figures/claims and empirical data. |
| **E-13** | `two-tier-xai-panel` | `evidence/AUDIT_ROUND2.md (Item 7.b)` | `92afc74` | `n/a...` | **DROPPED / UNVERIFIED** | Integrated directly into overlay UI implementation commit 92afc74. |
| **E-14** | `spf-dkim-drawer-states` | `evidence/E-14_spf-dkim-drawer-states/E-14_spf-dkim-drawer-states_test-output_20261107_799f152.txt` | `ef29590` | `c403616e54dca83e...` | **VALID** | Unit test execution log validating 3-state SPF/DKIM authentication drawer behaviors. |
| **E-15** | `virustotal-reasons-panel` | `evidence/AUDIT_ROUND2.md (Item 2.c)` | `95c6d12` | `n/a...` | **DROPPED / UNVERIFIED** | Documented in AUDIT_ROUND2.md Section 2.c. |
| **E-16** | `threshold-presets` | `evidence/AUDIT_FOR_MANUSCRIPT.md` | `a824a4e` | `n/a...` | **DROPPED / UNVERIFIED** | Implemented in dashboard UI (Conservative 35/65, Standard 45/75, Aggressive 55/85). |
| **E-17** | `post-defense-ui-commits` | `evidence/E-17_post-defense-ui-commits/E-17_post-defense-ui-commits_20261107_a824a4e.txt` | `f86cf64` | `ae8532d8f2ad143c...` | **VALID** | Git commit history log of post-defense prototype improvements and corrections. |
| **E-18** | `multitab-memory` | `N/A (Performance testing script)` | `n/a` | `n/a...` | **DROPPED / UNVERIFIED** | Multi-tab memory tracking dropped per faculty re-scoping. |
| **E-19** | `scan-trigger-ratelimit` | `evidence/E-19_scan-trigger-ratelimit/E-19_scan-trigger-ratelimit_refs_20261107_6a6ba94.md` | `aeaad62` | `83dbfc615246d8e6...` | **VALID** | Source code references confirming 300ms debounce and 15s VirusTotal pacing lock. |
| **E-20** | `test-set-composition` | `evidence/E-20_test-set-composition/E-20_test-set-composition_report_20261107_91e1e8d.md` | `d8ede2a` | `ee020941b225c1ce...` | **VALID** | Itemized categorical and syntactic composition report of the primary 100-email test set. |
| **E-21** | `model-provenance` | `evidence/E-21_model-provenance/E-21_model-provenance_20261107_320e9b3.md` | `85e8e3a` | `5206e0c8ece72ac3...` | **VALID** | Formal model card for DistilBERT ONNX sequence classifier detailing architecture and weights. |
| **E-22** | `taglish-test` | `evidence/E-42_philippine-taglish/E-42_philippine_evaluation.csv` | `11564ab` | `d2f04c892999ca31...` | **SUPERSEDED** | Superseded by comprehensive Round 2 Philippine/Taglish evaluation (E-42). |
| **E-23** | `uat-data` | `evidence/E-23_uat-data/E-23_uat-data_report_20261107_0c541f5.md` | `0c541f5` | `8662650409a25d72...` | **VALID** | Anonymized empirical survey responses (N=6 across 3 Philippine SMEs) and usability report. |
| **E-24** | `threshold-sweep` | `evidence/E-24_threshold-sweep/E-24_threshold-sweep_summary_20261108_0c541f5.csv` | `0c541f5` | `40dca27873584d1c...` | **VALID** | Receiver operating characteristic and sensitivity threshold sweep across cutoffs 20 to 80. |
| **E-25** | `citation-check` | `evidence/E-25_citation-check/E-25_citation-check_sources_20261107_a482063.md` | `a237ecd` | `f676f375027b88c3...` | **VALID** | Systematic audit of primary literature citations, DOIs, and retracted integration claims. |
| **E-26** | `primary-reports` | `evidence/AUDIT_FOR_MANUSCRIPT.md` | `a237ecd` | `n/a...` | **DROPPED / UNVERIFIED** | Consolidated into comprehensive manuscript audit documentation. |
| **E-27** | `gmail-use-confirmation` | `evidence/E-27_gmail-use-confirmation/E-27_gmail-use-confirmation_refs_20261107_a482063.md` | `a237ecd` | `9fbf6fa7f39bd942...` | **VALID** | Evidence confirming extension operates purely via DOM injection within Gmail web UI. |
| **E-28** | `in-memory-dict-check` | `evidence/E-28_in-memory-dict-check/E-28_in-memory-dict-check_refs_20261107_85e8e3a.md` | `6a6ba94` | `748667a8e03e8740...` | **VALID** | Source code citations proving volatile in-memory dictionary storage without backend database. |
| **E-29** | `fr01-fr08-wording` | `evidence/E-29_fr01-fr08-wording/E-29_fr01-fr08-wording_refs_20261107_a482063.md` | `a237ecd` | `1619c5094753341f...` | **VALID** | Audited revision matrix re-scoping FR01 (DOM scrape) and FR08 (advisory risk alert). |
| **E-30** | `revised-page-numbers` | `evidence/AUDIT_FOR_MANUSCRIPT.md` | `a237ecd` | `n/a...` | **DROPPED / UNVERIFIED** | Manuscript page reconciliation item. |
| **E-31** | `repro-package` | `evidence/E-31_repro-package/E-31_repro-package_v2readme_20261108_24be0d0.md` | `24be0d0` | `2cb3c4bd48a0d09e...` | **VALID** | Step-by-step reproduction instructions and asset integrity checksums for evaluation suite. |
| **E-32** | `nfr04-sample-size` | `evidence/E-32_nfr04-sample-size/E-32_nfr04-sample-size_v2output_20261107_0c541f5.txt` | `0c541f5` | `a230e1e02b390509...` | **VALID** | Statistical power calculation (Cochran / Clopper-Pearson) for N=100 test set. |
| **E-33** | `inter-rater` | `evidence/E-33_inter-rater/E-33_inter-rater_report_20261107_a482063.md` | `a237ecd` | `1c1f971f53d323f7...` | **VALID** | Formal inter-rater reliability methodology and quadratic weighted kappa protocol. |
| **E-34** | `transactional-fpr` | `evidence/E-34_transactional-fpr/E-34_transactional-fpr_report_20261108_0c541f5.txt` | `0c541f5` | `dde002ce71ccaa7b...` | **VALID** | False positive rate evaluation on 30 routine SME transactional/business notifications (FPR=0%). |
| **E-35** | `ph-brand-test` | `evidence/E-42_philippine-taglish/E-42_philippine_evaluation.csv` | `11564ab` | `d2f04c892999ca31...` | **SUPERSEDED** | Consolidated into E-42 Philippine benchmark evaluation. |
| **E-36** | `string-audit` | `evidence/E-36_string-audit/E-36_string-audit_20261107_fca8158.txt` | `320e9b3` | `729681b6bf9ad9fc...` | **VALID** | Comprehensive repository text scan verifying removal of unsupported marketing terms. |
| **E-37** | `shortener-unit-tests` | `aegis-backend/tests/test_link_scanner.py` | `8e9ce12` | `n/a...` | **DROPPED / UNVERIFIED** | URL shortener / redirect resolution tested in backend unit test suite. |
| **E-38** | `shortener-test-log` | `evidences/07_unit_tests_run.txt` | `8c42233` | `n/a...` | **DROPPED / UNVERIFIED** | Logged in unit test verification run. |
| **E-39** | `independent-corpus` | `evidence/E-39_round2_master_summary.json` | `11564ab` | `942d673c3e5e1975...` | **VALID** | Round 2 independent corpus evaluation on 250 external emails (SpamAssassin, Nazario, Enron). |
| **E-39-CALIB-R3** | `train-calibration` | `evidence/E-39_independent-corpus/E-39_train_calibration_report.json` | `19affee` | `5eb26bb36bf7d8b5...` | **SUPERSEDED** | SUPERSEDED: Round 3 fallback calibration on 200-email train split prior to warm-model rerun. |
| **E-39-NAZARIO-TEST** | `nazario-eval-json` | `evidence/E-39_independent-corpus/nazario_only_eval.json` | `untracked` | `b5adff217e29cb1f...` | **CONTAMINATED** | CONTAMINATED: Pure Nazario test evaluation (9 of 25 test samples overlap with train_200 split — SHA-256 recount 2026-11-09). |
| **E-40** | `layers-3-and-4` | `evidence/E-40_layers-3-and-4/E-40_live_vt_summary.json` | `untracked` | `adfa8a715fbc746c...` | **VALID** | Evaluation of behavioral anomaly detection and live rate-paced VirusTotal URL scans. |
| **E-41** | `ensemble-investigation` | `evidence/E-41_ensemble-investigation/E-41_weight_sensitivity_borderline.csv` | `11564ab` | `2b0c22c488ffebf7...` | **VALID** | Empirical investigation of ensemble ML weight contributions on borderline samples. |
| **E-42** | `philippine-taglish` | `evidence/E-42_philippine-taglish/E-42_philippine_evaluation.csv` | `11564ab` | `d2f04c892999ca31...` | **VALID** | Empirical evaluation of 60 Philippine English and Tagalog/Taglish phishing and legitimate emails. |
| **E-43** | `llm-authored-eval` | `evidence/E-43_llm-authored-eval/E-43_llm_predictions.csv` | `11564ab` | `ea2bf391d59860f5...` | **VALID** | Resilience evaluation against 60 LLM-authored phishing lures without explicit keyword cues. |
| **E-44** | `explainability-protocol` | `evidence/E-44_explainability-protocol/STUDY_PROTOCOL.md` | `11564ab` | `2418e8d89a424269...` | **VALID** | Complete human-subjects explainability evaluation protocol, consent, instruments, and scoring. |
| **E-45** | `small-fixes` | `evidence/E-45_small-fixes/live_render_telemetry_30warm_3cold_20261108_19affee.json` | `untracked` | `b53580436d4f7f2b...` | **VALID** | Empirical live Render container telemetry: 3 cold-start wakeups (mean 52.8s) + 30 warm requests. |

---

## Detailed Special Condition Audits

### 1. Withdrawn Benchmarks (E-05 & E-06)
- **Evidence IDs:** `E-05`, `E-06`
- **Formal Status:** `WITHDRAWN`
- **Forensic Cause:** `tools/run_phase_c_evaluations.py` and `scripts/evaluate_models.py` in early runs lacked runtime verification that `_session` was active. When run in offline environments without pre-warmed sessions, Layer 2 DistilBERT operated in fallback mode. Formally withdrawn from manuscript claims.

### 2. Superseded Calibration Runs (Round 3 Fallback Calibration)
- **Evidence File:** `evidence/E-39_independent-corpus/E-39_train_calibration_report.json` (initial run)
- **Formal Status:** `SUPERSEDED`
- **Forensic Cause:** In Round 3, `calibrate_warning_cutoff.py` ran before `warm_up_nlp()` was added, executing 200 train samples in fallback mode. Once `warm_up_nlp()` and the hard-abort guard were committed (`19affee`), the calibration was re-executed with genuine active DistilBERT weights.

### 3. Contaminated Test Set Disclosure (nazario_only_eval.json)
- **Evidence File:** `evidence/E-39_independent-corpus/nazario_only_eval.json`
- **Formal Status:** `CONTAMINATED`
- **Forensic Cause:** When evaluating pure Jose Nazario phishing emails vs public ham holdouts, **9 of the 25 Nazario test samples (36.0%)** originated from samples already present in `E-39_dataset_train_200.csv` due to independent random sampling from the parent corpus without deduplication against the training split. *(SHA-256 recount 2026-11-09 using exact split logic from `tools/evaluate_nazario_only.py` lines 47–50: `random.Random(42).shuffle` → `[100:125]`. Previous figure of "10" was incorrect.)* This contamination is formally disclosed and marked in all records.

---

## Notes on Audit Artifacts & Local Retention
AUDIT_ROUND3-5 and the FINAL_* reports are held in the authors' local copy and are not part of this commit. evidence/AGENT_LOG.md in the commit history records earlier agent operations.
