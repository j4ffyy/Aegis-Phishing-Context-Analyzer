# Objective 3-Point Comprehension Scoring Rubric (E-44)

The participant's open-ended verbatim explanation is scored by two independent raters using the following anchored 3-point rubric ($0, 1, 2$).

---

## Rubric Scoring Levels

### Score 0: Misunderstood / Inaccurate / Hazardous Interpretation
- **Definition:** The participant misinterprets the warning, perceives a dangerous threat as safe, or conversely interprets a safe email as an attack requiring disruption; fails to recognize the core intent.
- **Criteria / Indicators:**
  - Believes the email is safe when Aegis flags Warning or Critical.
  - Suggests complying with the attacker's demand (e.g., *"It says my password expired so I need to click the link to reset it"*).
  - States they do not understand what any part of the warning means (e.g., *"I have no idea what SPF or Levenshtein means"*).
- **Example Verbatim Responses (Scenario 3 - Critical):**
  - *"It means my bank account is in danger and I should follow the instructions in the email to fix it quickly."* $\rightarrow$ **Score 0**
  - *"There are technical codes on the screen, looks like computer errors."* $\rightarrow$ **Score 0**

---

### Score 1: Partial / Superficial Recognition of Risk Level
- **Definition:** The participant correctly identifies the high-level risk tier (e.g., that the email is suspicious or dangerous), but cannot explain **why** (lacks understanding of the specific indicator, such as spoofing, off-hours timing, or fake domains).
- **Criteria / Indicators:**
  - Relies solely on the color-coded badge or risk word without citing the causal evidence (e.g., *"It says Red / Critical so it's bad, but I don't know why"*).
  - Identifies a generic threat but misattributes the reason (e.g., *"It's a virus"* when the warning was domain spoofing).
- **Example Verbatim Responses (Scenario 2 - Warning):**
  - *"It's showing yellow so I need to be careful with this email."* $\rightarrow$ **Score 1**
  - *"It tells me this might not be safe, but I'm not sure what the sender did wrong."* $\rightarrow$ **Score 1**

---

### Score 2: Accurate Root-Cause Comprehension
- **Definition:** The participant accurately identifies both the risk level and the specific underlying causal indicator responsible for the alert (e.g., spoofed address, unfamiliar sender, unusual weekend timing, or fake website link).
- **Criteria / Indicators:**
  - Cites the specific causal mechanism explained in the overlay.
  - In Condition B (Plain Language): Articulates that the sender's address differs from the official domain, or that someone is sending unexpected payment changes late at night.
  - In Condition A (Technical): Correctly translates technical terms (e.g., recognizing SPF failure or domain mismatch means the sender is forged).
- **Example Verbatim Responses (Scenario 2 - Warning):**
  - *"It is warning me that the sender is using a .online website instead of our real vendor domain, and they never send emails on Saturday night."* $\rightarrow$ **Score 2**
  - *"The system says this is an unfamiliar sender trying to change bank accounts at off-hours, so it could be fraud."* $\rightarrow$ **Score 2**
- **Example Verbatim Responses (Scenario 3 - Critical):**
  - *"Aegis flagged this as a fake BDO email because the sender domain is fake and security scans confirmed the link goes to a credential harvesting site."* $\rightarrow$ **Score 2**

---

## Inter-Rater Reliability Protocol
- Two raters independently score all participant explanations blindly (unaware of condition assignment).
- Inter-rater agreement is computed using **Cohen's weighted quadratic kappa ($\kappa_w$)**.
- Discrepancies ($|R_1 - R_2| \ge 1$) are resolved through consensus discussion with a third senior adjudicator.
