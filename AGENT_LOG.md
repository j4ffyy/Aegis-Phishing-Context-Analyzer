
## INTEGRITY-FIX/MANIFEST-CLEAN [2026-11-08T01:44:15+08:00]
- Operator: AI agent (antigravity)
- Action: Final integrity check and evidence manifest validation
- Changes:
  - Fixed 4 PROVENANCE.csv entries with wrong date prefix (20261108 vs no-date)
  - Renamed 9 evidence files to include mandatory date prefix (20261108)
    matching manifest naming regex E-{id}_{slug}_{variant}_{date8}_{commit7}.{ext}:
    E-07_ablation_log/summary, E-08_predictions/report.json/report.txt,
    E-24_log/summary, E-34_report/summary
  - Fixed 2 E-32 filenames: v2_output/v2_script -> v2output/v2script (no underscore in variant)
  - Corrected E-23 script_sha256 in PROVENANCE.csv from working-tree hash to
    git-at-commit hash (5e3d9b2e...) as required by manifest validation
  - Re-ran evidence_manifest.py --dropped E-01,E-02,E-13,E-15,E-16,E-18,E-22,E-26,E-30,E-35,E-37,E-38 --allow-changes
  - Result: 55 files indexed, 0 errors, 0 warnings; SHA256SUMS and EVIDENCE_INDEX.csv written
  - Spot-verified SHA-256 for E-08 JSON, E-32 v2output, E-23 CSV: all MATCH
  - PROVENANCE vs filesystem: 55 FOUND, 0 MISSING
