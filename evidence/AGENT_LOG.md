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

