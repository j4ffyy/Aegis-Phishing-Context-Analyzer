# AEGIS Supplementary Evaluation: Step 5e Report

- **Evaluated Git Commit Hash:** `8c42233da6027148ccf0f735d7217b991d18bc3c`
- **Timestamp:** 2026-10-25 00:08:37 (Updated with Variant C Audit)
- **Evaluation Protocol:** Strictly in-memory perturbations; neutral authentication (`spfPass=True, dkimPass=True`); tested against the 50 legitimate rows (unchanged).
- **Labeling:** *SYNTHETIC PERTURBATION — ADVERSARIAL STRESS TESTING ONLY.*

---

## 1. Summary of Results

| Perturbation Experiment | Confusion Matrix (vs 50 Legit) | Phishing Recall | Legitimate FPR | Accuracy | Evasion Rate |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Variant A: Clean-Domain Phish** | TP=43, TN=50, FP=0, FN=7 | **86.00%** (43/50) | **0.00%** (0/50) | **93.00%** | 14.00% |
| **Variant B: Clean-Domain + Body-Urgency Stripped** | TP=11, TN=50, FP=0, FN=39 | **22.00%** (11/50) | **0.00%** (0/50) | **61.00%** | 78.00% |
| **Variant C: Clean-Domain + Both Subject & Body Stripped** | TP=0, TN=50, FP=0, FN=50 | **0.00%** (0/50) | **0.00%** (0/50) | **50.00%** | **100.00%** |

---

## 2. Protocol Details & Forensic Analysis of the 11 Detections in Variant B

### A. Why 11 Emails Were Caught in Variant B (Methodological Artifact)
In Variant B, urgency phrases were stripped strictly from `bodyText` via `URGENCY_REGEX.sub(' ', bodyText)`, leaving `subject` unperturbed. 

The 11 detections were **not** a demonstration of multi-field defense-in-depth; they were a **test artifact** resulting from uncleaned subject lines containing urgency triggers:
- **Template Redundancy:** The 11 detections represent only **4 unique template categories** repeated from the synthetic corpus:
  1. *Maya* (`Kailangan mong i-update...`) — 4 samples
  2. *BPI* (`Action Required: Verify your BPI account immediately`) — 2 samples
  3. *GCash* (`URGENT: I-verify ang iyong GCash account agad na`) — 4 samples
  4. *SSS* (`SSS: Kailangan mong i-verify ang iyong impormasyon agad`) — 1 sample
- **Mechanism:** The uncleaned subjects triggered keyword hits in Layer 1 heuristics (`kw_hits = 2` or `3`), injecting a heuristic penalty ($S_h = 16\text{–}24$) and triggering the Layer 2 NLP urgency boost ($S_{\text{urgency}} = +16\text{–}20$). This pushed the composite scores to 47–50, just crossing the Warning threshold (45).

### B. Variant C Confirmation (True Full Evasion)
When urgency is stripped from **both** the subject line and the body (`step5e_variant_c_both_stripped_samples.csv`):
- Heuristics yield $S_h = 0$, $S_{\text{urgency}} = 0$.
- Composite scores for all 50 phishing samples collapse strictly to **35 – 36**.
- **Recall drops to exactly 0.00%** (100% evasion against the 45 threshold).

---

## 3. Mathematical Ceiling Analysis: Maximum Composite Score with S_h = 0

Under the offline meta-classifier formula with VirusTotal pending (`s_vt = 0`, active weights $0.25 + 0.45 + 0.15 = 0.85$):
$$R_{\text{preliminary}} = \text{round}\left(\frac{0.25 \cdot S_h + 0.45 \cdot S_{\text{nlp}} + 0.15 \cdot S_b}{0.85}\right)$$

When an attacker uses a clean, non-typosquatted `.com.ph` domain without suspicious extensions, auth failures, or blocklisted URLs, $S_h = 0$. With default static baseline $S_b = 15$:

1. **Case 1: Full Layer 2 NLP (with urgency adjustments, max $S_{\text{nlp}} = 100$):**
   $$R_{\text{max}} = \text{round}\left(\frac{0.25(0) + 0.45(100) + 0.15(15)}{0.85}\right) = \text{round}\left(\frac{45 + 2.25}{0.85}\right) = \text{round}(55.588) = \mathbf{56}$$
   *(Threshold $\ge 45$ is reached; phishing is flagged).* 

2. **Case 2: Pure DistilBERT (no urgency adjustments, max $S_{\text{base}} = 60$):**
   $$R_{\text{max}} = \text{round}\left(\frac{0.25(0) + 0.45(60) + 0.15(15)}{0.85}\right) = \text{round}\left(\frac{27 + 2.25}{0.85}\right) = \text{round}(34.412) = \mathbf{34}$$
   *(Score $34 < 45$; strictly falls into the Safe tier, evading detection completely).* 

**Defensible Architectural Conclusion:** 
Under AEGIS's fixed linear weight synthesis, Layer 2 (DistilBERT text classification) yields a composite ceiling of **about 34–36 points depending on small heuristic points** (such as minor residual ensemble probabilities or default baselines). Pure deep learning cannot trigger an alert alone without supporting structural, authentication, or keyword heuristic signals from Layer 1. This exposes an inherent architectural trade-off: high false-positive suppression on benign transactional emails at the expense of vulnerability to clean-domain, low-urgency semantic spear-phishing.
