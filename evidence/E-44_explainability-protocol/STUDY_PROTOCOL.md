# Aegis Explainability & Usability Human Evaluation Protocol (E-44)

## 1. Study Title & Overview
**Study Title:** Empirical Assessment of Explainable AI (XAI) Presentation Modes on Threat Comprehension and Decision-Making Among Non-Technical SME Personnel  
**System Evaluated:** Aegis AI-Powered Phishing Context Analyzer (Chrome Extension v1.0.0, Two-Tier XAI Overlay)  
**Target Sample:** 8–10 non-technical administrative, accounting, or retail operations staff from Philippine Small and Medium Enterprises (SMEs).  
**Investigator Role:** Independent Protocol Administrator (Evaluation instruments administered by human proctor; automated agent does not execute human trials directly).  
**Execution Status:** Protocol specification only; the empirical study has not been run. All instruments, consent forms, and scoring templates are unexecuted and unpopulated for future administration.

---

## 2. Research Questions & Hypotheses
- **RQ1 (Comprehension):** Does the Aegis default plain-language narrative view (Toggle OFF) yield statistically higher threat comprehension scores compared to the technical telemetry view (Toggle ON) among non-technical SME personnel?
- **RQ2 (Action Correctness):** Does plain-language threat translation increase the proportion of safe operational decisions (reporting or out-of-band verification) when encountering high-risk correspondence?
- **RQ3 (Efficiency & Usability):** How does the plain-language view impact decision latency (time-to-decision), and what is the resulting perceived usability score (SUS)?

---

## 3. Experimental Design (Within-Subjects Counterbalanced)
To prevent order and learning effects, the evaluation employs a **$2 \times 2$ Latin Square Counterbalanced Design**:
- **Factor 1 (Interface Condition):**
  - **Condition A (Toggle OFF - Plain-Language View [Default UI State]):** Displays simplified categorical badges (`Sender Legitimacy`, `Message Tone`, `File Attachments`) with actionable, non-technical plain-language explanations designed for general retail and office personnel.
  - **Condition B (Toggle ON - Technical View):** Displays raw engineering telemetry, cryptographic header verification status (`SPF: Pass`, `DKIM: Pass`, `DMARC: None`), brand typosquatting Levenshtein distance metrics, and per-layer model probability scores.
- **Factor 2 (Scenario Archetypes):**
  - **Scenario 1 (Safe Tier, Score: 14/100):** Legitimate corporate invoice notification with valid cryptographic authentication.
  - **Scenario 2 (Warning Tier, Score: 52/100):** Unfamiliar supplier payment redirection with subtle typosquatting and timing anomaly.
  - **Scenario 3 (Critical Tier, Score: 85/100):** Urgent executive wire fraud / account lock lure containing a flagged link.

### Latin Square Counterbalance Matrix:
| Participant ID | First 3 Scenarios | Second 3 Scenarios |
| :--- | :--- | :--- |
| **P01 – P05 (Group 1)** | Condition A (Plain-Language View, Toggle OFF) | Condition B (Technical View, Toggle ON) |
| **P06 – P10 (Group 2)** | Condition B (Technical View, Toggle ON) | Condition A (Plain-Language View, Toggle OFF) |

---

## 4. Experimental Procedure
1. **Pre-Test Briefing (5 mins):** Welcome participant, administer Participant Information Sheet & Consent Form (`PARTICIPANT_CONSENT.md`), explain that the study evaluates the software interface, not user competence.
2. **Familiarization (3 mins):** Participant views an un-scored neutral email to observe overlay positioning.
3. **Execution Phase (15–20 mins):**
   - For each scenario, participant reads the email and views the Aegis scan overlay in the designated condition.
   - **Task 1 (Comprehension):** Participant states in their own words: *"Explain what this alert is telling you about this email."* (Recorded verbatim and scored via 3-point rubric).
   - **Task 2 (Action Choice):** Participant selects an immediate action from 4 standardized choices (A: Proceed/Click, B: Reply to sender, C: Verify out-of-band via phone/Slack, D: Report & Delete).
   - **Task 3 (Latency):** Proctor records task completion time (from overlay appearance to final action choice) in seconds.
4. **Post-Test Usability Survey (5 mins):** Participant completes the standard 10-item System Usability Scale (`SUS_QUESTIONNAIRE.md`).
5. **Debriefing (2 mins):** Proctor reveals simulated nature of phishing emails, answers questions, and concludes trial.

---

## 5. Metrics & Dependent Variables
1. **Threat Comprehension Score (0–2 scale):** Evaluated against the objective rubric (`SCORING_RUBRIC.md`).
2. **Correct Action Rate (%):** Proportion of trials where the participant selects the security-policy compliant action.
3. **Decision Latency ($T_{\text{task}}$, seconds):** Time elapsed between email opening and action selection.
4. **System Usability Scale (SUS, 0–100):** Standard Brooke (1996) composite usability score.

