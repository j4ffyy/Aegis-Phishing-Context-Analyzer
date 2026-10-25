# AEGIS Supplementary Evaluation Summary Table

- **Evaluated Git Commit Hash:** `8c42233da6027148ccf0f735d7217b991d18bc3c`
- **Evaluation Dataset:** `aegis-backend/data/test_dataset.csv` (N=100: 50 phishing / 50 legitimate)
- **Execution Timestamp:** 2026-10-24 23:29:43

| Experiment / Configuration | Accuracy (%) | Precision (%) | Recall (%) | FPR (%) | F1-Score (%) | ROC-AUC [95% Boot CI] | Notes / Protocol |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Submitted Benchmark (Synthetic Auth: 100% Phish Fail, 0% Legit Fail) | 93.00% [86.3%, 96.6%] | 100.00% | 86.00% [73.8%, 93.0%] | 0.00% [0.0%, 7.1%] | 92.47% | 0.9924 [0.9836, 1.0000] | Submitted baseline; full pipeline; synthetic auth label leakage present |
| Submitted Control (Neutral Auth: All Pass) | 83.00% [74.5%, 89.1%] | 100.00% | 66.00% [52.2%, 77.6%] | 0.00% [0.0%, 7.1%] | 79.52% | 0.9980 [0.9925, 1.0000] | Submitted control; full pipeline with auth penalties disabled |
| Task A: 1. Layer 1 heuristics only (ensemble off) | 92.00% [85.0%, 95.9%] | 100.00% | 84.00% [71.5%, 91.7%] | 0.00% [0.0%, 7.1%] | 91.30% | 0.9980 [0.9925, 1.0000] | Ablation run under neutral auth (threshold >= 45) |
| Task A: 2. Layer 1 heuristics + RF/XGBoost ensemble | 79.00% [70.0%, 85.8%] | 100.00% | 58.00% [44.2%, 70.6%] | 0.00% [0.0%, 7.1%] | 73.42% | 0.9976 [0.9904, 1.0000] | Ablation run under neutral auth (threshold >= 45) |
| Task A: 3. NLP layer incl. rule adjustments | 92.00% [85.0%, 95.9%] | 100.00% | 84.00% [71.5%, 91.7%] | 0.00% [0.0%, 7.1%] | 91.30% | 0.9956 [0.9869, 1.0000] | Ablation run under neutral auth (threshold >= 45) |
| Task A: 4. Layer 1 + Layer 2, ensemble off | 92.00% [85.0%, 95.9%] | 100.00% | 84.00% [71.5%, 91.7%] | 0.00% [0.0%, 7.1%] | 91.30% | 0.9980 [0.9925, 1.0000] | Ablation run under neutral auth (threshold >= 45) |
| Task A: 5. Full pipeline as submitted | 83.00% [74.5%, 89.1%] | 100.00% | 66.00% [52.2%, 77.6%] | 0.00% [0.0%, 7.1%] | 79.52% | 0.9980 [0.9925, 1.0000] | Ablation run under neutral auth (threshold >= 45) |
| Task A: 6. DistilBERT only (pure) | 50.00% [40.4%, 59.6%] | 0.00% | 0.00% [0.0%, 7.1%] | 0.00% [0.0%, 7.1%] | 0.00% | 0.5000 [0.5000, 0.5000] | Ablation run under neutral auth (threshold >= 45) |
| Task B: Realistic-Auth Sensitivity (Seed 42) | 92.00% [85.0%, 95.9%] | 100.00% | 84.00% [71.5%, 91.7%] | 0.00% [0.0%, 7.1%] | 91.30% | N/A (Binary auth trial) | Assumed model: P(fail|phish)=0.40, P(fail|legit)=0.03, Seed=42 |
| Task B: Realistic-Auth Sensitivity (200 Seeds Distribution) | Mean 87.15% [84.00%, 90.00%] | Mean 100.00% | Mean 74.30% [68.00%, 80.00%] | Mean 0.00% [0.00%, 0.00%] | Mean 85.21% | N/A (Distribution across seeds) | Assumed-rate sensitivity: 200 random seeds (2.5th–97.5th percentiles) |
| Task C: Weight Sensitivity Sweep (27 Distinct Outcomes) | Range: [67.00%, 91.00%] | 100.00% across all 27 | Range: [34.00%, 82.00%] | Range: [0.00%, 0.00%] | N/A (Multi-point range) | N/A (Multi-point sweep) | Grid sweep of weights +/- 0.10 (neutral auth, w_vt cancelled offline) |
