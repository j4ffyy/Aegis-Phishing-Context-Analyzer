# Aegis User Acceptance Testing (UAT) & Usability Evaluation Report (E-23)

- **Evidence ID:** E-23
- **Generated:** 2026-11-07T17:19:16.797719+00:00
- **Commit:** `0c541f5`
- **Data Source:** XLSX (actual survey spreadsheet — no hardcoded fallback used)
- **Source File:** `Aegis-Phishing-Context-Analyzer (Responses).xlsx`
- **Source SHA-256:** `7e7a21a212262f126bea6e8d888bf32aa21d3207da9fabe6cbe3a4218fac64fc`
- **Evaluation Date:** October 9, 2026
- **Sample Scope:** N = 6 participants across 3 distinct Philippine micro-enterprises and small businesses

---

## 1. Executive Summary & Methodological Scope

- The evaluation cohort comprises **three distinct micro-enterprises and small businesses** (< 50 employees), with exactly **one business owner and one operational staff member** evaluated per enterprise (total $N = 6$).
- The study demonstrates **preliminary qualitative usability and workflow non-intrusiveness** within micro/small enterprise contexts.
- It is acknowledged that this sample does not establish general deployment readiness across medium-sized enterprises (100–199 employees), as reflected in manuscript Chapter 4 and Chapter 5.

## 2. Participant Composition Table

| Respondent ID | Company ID | Business Category | Enterprise Size Classification | Role Category | Role Description |
|---|---|---|---|---|---|
| R01 | SME-01 | Mini Grocery / Retail | Micro-enterprise (< 10 employees) | Owner | Mini Grocery Owner |
| R02 | SME-02 | Dental Clinic & Gym Facility | Small Business (< 50 employees) | Owner | Dentist / Gym Owner / Businessman |
| R03 | SME-03 | Commercial Trading & Services | Small Business (< 50 employees) | Owner | Commercial Business Owner |
| R04 | SME-01 | Mini Grocery / Retail | Micro-enterprise (< 10 employees) | Staff | Grocery Operations Staff |
| R05 | SME-02 | Dental Clinic & Gym Facility | Small Business (< 50 employees) | Staff | Dental / Gym Administrative Staff |
| R06 | SME-03 | Commercial Trading & Services | Small Business (< 50 employees) | Staff | Administrative Office Staff |

## 3. Quantitative Usability Findings

Survey questions evaluated on a 5-point Likert scale (1 = Poor/Disruptive, 5 = Highly Favorable/Seamless):
- **Q1 (Speed):** Perception of scanning latency upon opening webmail.
- **Q2 (Accuracy):** User-perceived fidelity of Safe / Warning / Critical risk tier designations.
- **Q3 (Comprehension):** Clarity and readability of Explainable AI (XAI) plain-language explanations.
- **Q4 (Workflow Non-Intrusiveness):** Freedom from interruption during routine email handling.

### Summary Breakdown by Role

| Metric / Domain | Business Owners ($N=3$) | Operational Staff ($N=3$) | Combined Cohort ($N=6$) |
|---|---|---|---|
| Q1: Processing Speed | 4.33 / 5.0 (86.7%) | 5.00 / 5.0 (100.0%) | **4.67 / 5.0 (93.3%)** |
| Q2: Perceived Accuracy | 4.33 / 5.0 (86.7%) | 5.00 / 5.0 (100.0%) | **4.67 / 5.0 (93.3%)** |
| Q3: XAI Comprehension | 4.33 / 5.0 (86.7%) | 5.00 / 5.0 (100.0%) | **4.67 / 5.0 (93.3%)** |
| Q4: Workflow Non-Intrusiveness | 4.33 / 5.0 (86.7%) | 5.00 / 5.0 (100.0%) | **4.67 / 5.0 (93.3%)** |
| **Overall Composite Usability** | **4.33 / 5.0 (86.7%)** | **5.00 / 5.0 (100.0%)** | **4.67 / 5.0 (93.3%)** |

## 4. Qualitative Observations & XAI Insights
1. **Owner Scrutiny vs. Staff Trust:** Business owners gave conservative ratings (4.0/5.0 across SME-02 and SME-03), noting that they actively read the plain-language XAI points before opening links or attachments. Operational staff rated all dimensions 5.0/5.0, citing the visual drawer indicator as an intuitive guide.
2. **Zero Reported Operational Disruptions:** Neither group encountered browser lock-ups or DOM degradation during active Gmail usage, consistent with the client-side debounce (300 ms) and local caching telemetry.
3. **Scope Alignment:** These findings corroborate FR07 (XAI readability) and FR08 (visual alert banner) under authentic Philippine SME operating conditions.
