# Code & Formula Reference: Aegis Multi-Layer Composite Scoring Engine (E-10)

- **Evidence ID:** `E-10`
- **Canonical Slug:** `scoring-formula-code`
- **Revision Matrix Rows Addressed:** Row 11 (Sir John Ray Hernani, Panel Chair — Scoring weights lack mathematical defensibility; Flower Shop scenario)
- **Repository Commit:** `91e1e8d` (eval-freeze)
- **Date (UTC):** 2026-11-07
- **Verification Status:** Verified against source code in `aegis-backend/modules/meta_classifier.py` and `aegis-backend/routes/analyze.py`.

---

## 1. Executive Summary & Defense Response

During the post-defense evaluation, the Panel Chair noted:
> *"Scoring weights lack mathematical defensibility (V10): weights (0.25/0.45/0.15/0.15) are hand-set constants. The 0.45 NLP weight justification collapses if DistilBERT provides no proven incremental value over heuristics. Alert-fatigue 'Flower Shop' scenario: SPF Fail + DKIM Fail + First-Time Sender = Warning for legitimate new customers."*

This document provides exact line-by-line source code citations for the composite scoring architecture, confirming:
1. The 4 analytical weights are hand-set empirical constants ($w_h=0.25, w_{nlp}=0.45, w_b=0.15, w_{vt}=0.15$).
2. Dynamic normalization applies when VirusTotal targets are absent or pending ($w_h'=0.294, w_{nlp}'=0.529, w_b'=0.176$).
3. The empirical behavior of the "Flower Shop" false-positive scenario where benign order inquiries are elevated into the Warning tier due to compounding authentication failures, baseline novelty, and DistilBERT transactional token confusion.

---

## 2. Source Code Citations

### 2.1 Layer Weight Definitions
- **File:** `aegis-backend/modules/meta_classifier.py`
- **Lines 18–37:**
```python
# Layer 1: Heuristics & Syntactic Rule Engine
WEIGHT_HEURISTIC: float = 0.25

# Layer 2: Deep NLP Context Intent Analysis (DistilBERT ONNX 4-class)
WEIGHT_NLP: float = 0.45

# Layer 3: Client-Side Behavioral Profiling & Baseline Deviations
WEIGHT_BEHAVIORAL: float = 0.15

# Layer 4: External Threat Intelligence (VirusTotal v3)
WEIGHT_VT: float = 0.15

# Risk Tier Threshold Constants (§3.3)
TIER_SAFE_MAX: int = 44        # Score 0-44  -> Safe
TIER_WARNING_MIN: int = 45     # Score 45-74 -> Warning
TIER_WARNING_MAX: int = 74     # Score 45-74 -> Warning
TIER_CRITICAL_MIN: int = 75    # Score 75-100 -> Critical
```

### 2.2 Composite Formulation & Dynamic Renormalization
- **File:** `aegis-backend/modules/meta_classifier.py`
- **Lines 49–97 (`synthesize_composite_score`):**
When external hyperlink/attachment targets are absent or pending analysis, $w_{vt}$ is dropped and remaining weights re-normalize over $(w_h + w_{nlp} + w_b = 0.85)$:
$$w_h' = \frac{0.25}{0.85} \approx 0.2941, \quad w_{nlp}' = \frac{0.45}{0.85} \approx 0.5294, \quad w_b' = \frac{0.15}{0.85} \approx 0.1765$$
```python
if vt_pending:
    total_active_weight = WEIGHT_HEURISTIC + WEIGHT_NLP + WEIGHT_BEHAVIORAL  # 0.85
    composite = (
        (s_heuristic * WEIGHT_HEURISTIC) +
        (s_nlp * WEIGHT_NLP) +
        (s_behavioral * WEIGHT_BEHAVIORAL)
    ) / total_active_weight
else:
    composite = (
        (s_heuristic * WEIGHT_HEURISTIC) +
        (s_nlp * WEIGHT_NLP) +
        (s_behavioral * WEIGHT_BEHAVIORAL) +
        (s_vt * WEIGHT_VT)
    )
```

### 2.3 Threat Floor Rules (§6.5)
- **File:** `aegis-backend/modules/meta_classifier.py`
- **Lines 400–435 (`synthesize_assessment`):**
1. **Critical Threat Floor ($S_{final} \ge 75$):**
   If VirusTotal confirms a malicious link or attachment signature ($S_{vt} \ge 75$), score is bounded below by 75 (Critical), regardless of whether sender has high historical familiarity.
2. **Multi-Indicator Warning Threat Floor ($S_{final} \ge 52$):**
   Triggered when either:
   - Both an attachment threat and an urgency/NLP threat ($S_{nlp} \ge 25$) are present, OR
   - Raw heuristic risk $S_h \ge 40$ (e.g. SPF + DKIM both fail: $25 + 20 = 45 \ge 40$).
   Prevents threat dilution into "Safe" by absence of external links or behavioral anomalies.

---

## 3. The "Flower Shop" Scenario Proof

### 3.1 Scenario Definition
A legitimate local business (e.g., *Island Blooms Florist*) contacts an SME employee for the first time regarding a floral invoice:
1. **Authentication:** The small vendor's domain lacks configured SPF and DKIM DNS records (`spfPass=False`, `dkimPass=False`).
   - Heuristic penalty: $+25$ (SPF) $+ 20$ (DKIM) $\to S_h = 45$.
2. **Behavioral Profile:** The vendor has never emailed this company before.
   - First-time sender baseline: $S_b = 25$.
3. **Hyperlinks:** No hyperlinks or attachments included $\to S_{vt} = 0$ (VT pending/inactive mode).
4. **NLP Semantic Intent:** Email body contains standard transactional language:
   > *"Good day, please find attached the details of your floral arrangement delivery for this Friday. Kindly confirm delivery address and contact person."*
   - DistilBERT ONNX evaluates the sub-token vocabulary for "delivery", "payment", "confirm". Because these tokens overlap credential-harvesting phishing templates, DistilBERT outputs $P_{phish} = 0.9998$, generating $S_{nlp} = 60$ (verified in `E-09`).

### 3.2 Resulting Score Calculation
Applying the 3-layer renormalized formula:
$$S = \frac{0.25(45) + 0.45(60) + 0.15(25)}{0.85} = \frac{11.25 + 27.0 + 3.75}{0.85} = \frac{42.0}{0.85} = 49.41 \xrightarrow{\text{round}} 49$$
Furthermore, because $S_h = 45 \ge 40$, the Multi-Indicator Warning Floor (§6.5) elevates the score to **52**.

### 3.3 Final Classification
- **Risk Score:** 52%
- **Risk Tier:** **Warning (Amber)**
- **Consequence:** Non-technical staff receive an active warning banner advising them not to trust a legitimate business inquiry. This confirms the panel's finding: compounding non-malicious failure flags create alert fatigue for benign external partners.

---

## 4. Manuscript Integration Note
In accordance with Plan §2 and Section 4.5, these findings will be honestly reflected in Chapter 3 (Section 3.3) and Chapter 4 (Section 4.6), explicitly identifying hand-tuned linear weights and semantic false-positives on transactional text as known limitations. Production weights remain frozen to maintain evidence reproducibility across defense audits.
