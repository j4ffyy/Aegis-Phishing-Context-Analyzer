# Step 6 — Documentation Consistency Summary Table

Evaluated Commit: 8c42233da6027148ccf0f735d7217b991d18bc3c  
Audit Date: 2026-10-25  
All evidence read-only from source files — no edits made.

| # | Item Checked | Claimed | Actual | Verdict |
|:---:|:---|:---|:---|:---:|
| 1 | README Layer 1 (Heuristics + Ensemble) | Active: rules + typosquatting + RF/XGB ensemble | CONFIRMED: evaluate_layer1() blends S_L1 = 0.60*S_h + 0.40*S_ens; pkl models loaded | CORRECT |
| 2 | README Layer 2 (DistilBERT ONNX) | Active: DistilBERT ONNX, without fine-tuning | INCORRECT for submitted run (89e4948): evaluate_models.py never called load_nlp_model(); all samples scored via _fallback_classification() returning S_base=20 or 10 | MISMATCH |
| 3 | README Layer 3 (Behavioral) | Neutralized: S_behavioral = 15 constant | CONFIRMED: evaluate_behavioral() returns 15; used in all formula calls | CORRECT |
| 4 | README Layer 4 (VirusTotal) | Skipped offline | CONFIRMED: s_vt=0, vt_pending=True in synthesize_composite_score() | CORRECT |
| 5 | README commit hash (89e4948) | Evaluated build = 89e4948 (PR-08/PR-09 merged) | PARTIALLY OUTDATED: README edited at 8c42233 but still cites 89e4948 as evaluated build. 89e4948 is correct for initial evidence run; 8c42233 added per_sample CSVs and neutral auth | PARTIALLY OUTDATED |
| 6 | Paper commit hash (c766732) | Evaluated at commit c766732 | INCORRECT: c766732 is a deploy-only commit (2026-10-22 17:50) that changed main.py + manifest.json to link Render URL. test_dataset.csv did not exist until 89e4948 (2026-10-23 11:59). Evaluation could not have been run at c766732. | INCORRECT — PREDATES DATASET |
| 7 | 03_evaluation_report.txt latency p50 = 50.8 ms | p50 = 50.8 ms, avg = 65.0 ms | Produced at commit 89e4948 (first run). No per-sample CSV saved. Five checkpoint lats in log (57.1/56.7/46.2/58.1/53.2 ms at rows 20/40/60/80/100) are consistent with p50~50ms. Different execution session on Windows workstation. | AUTHENTIC — SEPARATE RUN |
| 8 | evaluation_report.txt latency p50 = 68.0 ms | p50 = 68.0 ms, avg = 91.9 ms | Produced at commit 8c42233 (second run). per_sample_evaluation.csv confirms avg=91.87, p50=67.98. Row id=24 has elapsed=2160.99ms (ONNX cold-start, first inference of session), inflating avg. | AUTHENTIC — SEPARATE RUN |
| 9 | Both reports: same classification results | TP=43 TN=50 FP=0 FN=7 in both | CONFIRMED: identical confusion matrix in both files. Latency differs; classification does not. Both used _fallback_classification() (neither loaded DistilBERT). | CONSISTENT |
