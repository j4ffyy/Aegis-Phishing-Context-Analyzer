# Test Dataset Inter-Rater Reliability Audit (E-33)

- **Evidence ID:** E-33
- **Produced By:** I-06 / Dataset Provenance Review
- **Commit:** `a482063`
- **Specification:** AEGIS Implementation Plan v3.2 §4.2, §7 (I-06) & Post Defense Feedback

---

## 1. Status: Formal Multi-Annotator Inter-Rater Agreement Not Conducted

In accordance with Plan §2 (Integrity Rules: zero fabricated metrics) and Plan §7 (Item I-06 / E-33: *"md or csv (kappa, or 'not conducted')"*), this report formally records that:

> **A formal dual-blind inter-rater reliability study (such as Cohen's Kappa or Fleiss' Kappa) was NOT conducted across independent human annotators for the 100-sample test dataset (`test_dataset.csv`).**

---

## 2. Dataset Annotation Methodology & Known Limitations

1. **Annotation Origin:** Ground-truth classification labels ($0 = \text{Legitimate}, 1 = \text{Phishing}$) were assigned during initial prototype development by the student development team rather than through independent dual-blind expert consensus.
2. **Synthetic Cue Contamination (E-20):**
   - As established in `E-20_test-set-composition_report_20261107_91e1e8d.md`, 100% of phishing emails were assigned synthetic authentication failures (`spfPass=False`, `dkimPass=False`), and 100% of legitimate emails were assigned passes (`spfPass=True`, `dkimPass=True`).
   - Consequently, true label assignment was perfectly correlated with synthetic authentication flags, removing label ambiguity during dataset creation.
3. **Statistical Power Limitation (E-32):**
   - With $N = 50$ phishing samples, confidence intervals are wide (Wilson 95% CI spans $\pm 12.8\%$).
   - Validating inter-annotator agreement on borderline or ambiguous samples (e.g. benign transactional receipts with aggressive marketing language) requires a dedicated multi-annotator protocol on an expanded corpus.

---

## 3. Academic Reporting Directives

1. **No Phantom Kappa Score:** The manuscript must NOT claim any arbitrary Cohen's Kappa value (e.g., $\kappa = 0.85$).
2. **Explicit Limitation Disclosure:** Chapter 3 (Section 3.4) and Chapter 5 (Section 5.2) will explicitly disclose that formal inter-rater agreement was not conducted, noting dataset labeling provenance as an academic limitation to be resolved in future multi-institutional research.
